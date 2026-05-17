/* global describe, it */
"use strict";

const { expect } = require("chai");
const net = require("net");
const http = require("http");

describe("Security: buildURL SSRF prevention", () => {
  const { buildURL } = require("../lib/utils");

  it("should allow relative paths within base", () => {
    const url = buildURL("/hi", "http://localhost:3000");
    expect(url.origin).to.equal("http://localhost:3000");
  });

  it("should block absolute URL bypassing base", () => {
    expect(() => buildURL("http://evil.com/admin", "http://127.0.0.1:3000"))
      .to.throw(/SSRF prevention/);
  });

  it("should block HTTPS absolute URL bypass", () => {
    expect(() => buildURL("https://internal/api", "http://127.0.0.1:3000"))
      .to.throw(/SSRF prevention/);
  });

  it("should allow absolute URL when no base", () => {
    const url = buildURL("http://target.com/api");
    expect(url.href).to.equal("http://target.com/api");
  });

  it("should sanitize protocol-relative within base", () => {
    const url = buildURL("//evil.com/hi", "http://localhost");
    expect(url.origin).to.equal("http://localhost");
  });
});

describe("Security: hop-by-hop header stripping", () => {
  const { stripHttp1ConnectionHeaders } = require("../lib/utils");

  it("should strip transfer-encoding", () => {
    const h = { "transfer-encoding": "gzip, chunked", "x-custom": "val" };
    const r = stripHttp1ConnectionHeaders(h);
    expect(r).to.not.have.property("transfer-encoding");
    expect(r).to.have.property("x-custom", "val");
  });

  it("should strip connection and keep-alive", () => {
    const h = { connection: "close", "keep-alive": "t=5", "x-data": "ok" };
    const r = stripHttp1ConnectionHeaders(h);
    expect(r).to.not.have.property("connection");
    expect(r).to.not.have.property("keep-alive");
    expect(r).to.have.property("x-data", "ok");
  });

  it("should strip host header from response", () => {
    const h = { host: "evil.com", "content-type": "text/plain" };
    const r = stripHttp1ConnectionHeaders(h);
    expect(r).to.not.have.property("host");
    expect(r).to.have.property("content-type", "text/plain");
  });
});

describe("Security: SSRF end-to-end proxy", () => {
  let gateway, service, close, proxy, gHttpServer;

  it("setup", async () => {
    const fastProxy = require("../index")({ base: "http://127.0.0.1:3000" });
    close = fastProxy.close;
    proxy = fastProxy.proxy;
    gateway = require("restana")();
    gateway.all("/*", (req, res) => proxy(req, res, req.url, {}));
    gHttpServer = await gateway.start(8080);
    service = require("restana")();
    service.get("/service/get", (req, res) => res.send("OK"));
    service.get("/service/evil", (req, res) => {
      res.setHeader("transfer-encoding", "gzip, chunked");
      res.setHeader("keep-alive", "timeout=99");
      res.setHeader("x-custom", "downstream");
      res.end("evil");
    });
    await service.start(3000);
  });

  it("should block SSRF via absolute-form request", (done) => {
    // Use raw http.createServer instead of restana because
    // restana routes cannot match absolute-form req.url values.
    const fastProxy = require("../index")({ base: "http://127.0.0.1:3000" });
    const { proxy, close } = fastProxy;
    const server = http.createServer((req, res) => {
      proxy(req, res, req.url, {});
    });
    server.listen(0, () => {
      const port = server.address().port;
      const c = net.connect(port, "127.0.0.1", () => {
        c.write("GET http://169.254.169.254/latest HTTP/1.1\r\n");
        c.write("Host: 127.0.0.1\r\n");
        c.write("Connection: close\r\n\r\n");
      });
      let d = "";
      c.on("data", ch => { d += ch.toString(); });
      c.on("end", () => {
        expect(d).to.include("400");
        // 400 status + normal proxy still functional after SSRF attempt
        close();
        server.close();
        done();
      });
      c.on("error", done);
    });
  });it("should strip hop-by-hop headers end-to-end", async () => {
    const res = await require("supertest")(gHttpServer)
      .get("/service/evil")
      .expect(200);
    expect(res.headers["transfer-encoding"]).to.not.equal("gzip, chunked");
    expect(res.headers["keep-alive"]).to.not.equal("timeout=99");
    expect(res.headers["x-custom"]).to.equal("downstream");
  });

  it("teardown", async () => {
    close();
    await gateway.close();
    await service.close();
  });
});