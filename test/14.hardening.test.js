/* global describe, it, before, after */
'use strict'

const { expect } = require('chai')
const http = require('http')
const http2 = require('http2')
const net = require('net')
const { EventEmitter } = require('events')
const { PassThrough } = require('stream')
const bodyParser = require('body-parser')
const fastProxy = require('../index')

function listen (server, host = '127.0.0.1') {
  return new Promise(resolve => server.listen(0, host, () => resolve(server.address().port)))
}

// tracks the raw connections of a server, so it can always be closed
function track (server) {
  server.sockets = new Set()
  server.on('connection', socket => {
    server.sockets.add(socket)
    socket.on('close', () => server.sockets.delete(socket))
  })

  return server
}

function closeServer (server) {
  return new Promise(resolve => {
    server.close(resolve)
    if (server.closeAllConnections) server.closeAllConnections()
    if (server.sockets) server.sockets.forEach(socket => socket.destroy())
  })
}

function sleep (ms) {
  return new Promise(resolve => setTimeout(resolve, ms))
}

// sends a raw payload and resolves with everything received until the
// connection is closed by the peer, or the timeout expires
function raw (port, payload, timeout = 1000) {
  return new Promise(resolve => {
    const socket = net.connect(port, '127.0.0.1', () => socket.write(Buffer.from(payload, 'latin1')))
    let data = ''
    let closedByPeer = false
    const timer = setTimeout(() => socket.destroy(), timeout)
    socket.on('data', chunk => { data += chunk.toString('latin1') })
    socket.on('end', () => { closedByPeer = true })
    socket.on('error', () => { closedByPeer = true })
    socket.on('close', () => {
      clearTimeout(timer)
      resolve({ data, closedByPeer, status: +data.slice(9, 12), body: data.slice(data.indexOf('\r\n\r\n') + 4) })
    })
  })
}

// remote server that records the exact bytes it receives
function wireServer (reply = 'HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok') {
  const state = { wire: '' }
  const server = track(net.createServer(socket => {
    socket.on('error', () => {})
    socket.on('data', chunk => {
      state.wire += chunk.toString('latin1')
      clearTimeout(socket.timer)
      socket.timer = setTimeout(() => socket.write(reply), 50)
    })
  }))
  state.server = server

  return state
}

describe('Hardening: request target validation', () => {
  const { buildURL } = require('../lib/utils')

  it('should reject dot segments', () => {
    const sources = [
      '/service/../admin',
      '/service/..',
      '/service/./admin',
      '/service/.',
      '/service/%2e%2e/admin',
      '/service/%2E%2E/admin',
      '/service/.%2e/admin',
      '/service/%2e./admin',
      '/service/%2e/admin',
      '../admin',
      '..',
      '.',
      'http://localhost/service/../admin'
    ]
    for (const source of sources) {
      expect(() => buildURL(source, 'http://localhost'), source).to.throw(/Unsafe path/)
    }
  })

  it('should reject backslashes and control characters in the path', () => {
    for (const source of ['/service\\admin', '/service/x\\..\\..\\admin', '\\\\evil.com/x', '/\\evil.com', '/ser\tvice', '/.\n./admin', '/a\r/b']) {
      expect(() => buildURL(source, 'http://localhost'), JSON.stringify(source)).to.throw(/Unsafe path/)
    }
  })

  it('should not reject safe paths', () => {
    const sources = {
      '/.well-known/security.txt': '/.well-known/security.txt',
      '/a/..b/c': '/a/..b/c',
      '/a/.../c': '/a/.../c',
      '/a/b..': '/a/b..',
      '/a/%2e%2ehidden': '/a/%2e%2ehidden',
      '/a?next=/../b&c=\\d': '/a',
      '/a#/../b': '/a',
      '/a%2f..%2fb': '/a%2f..%2fb',
      '/a%5c..%5cb': '/a%5c..%5cb',
      '': '/'
    }
    for (const source of Object.keys(sources)) {
      expect(buildURL(source, 'http://localhost').pathname, source).to.equal(sources[source])
    }
  })

  it('should keep the query string untouched', () => {
    expect(buildURL('/a?next=/../b&c=\\d', 'http://localhost').search).to.equal('?next=/../b&c=\\d')
  })

  it('should reject unsupported protocols', () => {
    for (const source of ['ftp://example.com/x', 'file:///etc/passwd', 'ws://example.com/', 'javascript:alert(1)', 'data:text/plain,hi']) {
      expect(() => buildURL(source), source).to.throw()
    }
    expect(() => buildURL('/x', 'ftp://example.com')).to.throw(/Unsupported protocol/)
  })

  it('should reject non string sources', () => {
    expect(() => buildURL({ toString: () => '/x' }, 'http://localhost')).to.throw(TypeError)
  })

  it('should block origin escapes', () => {
    const sources = [
      'http://localhost@evil.com/',
      'http://localhost:81/',
      'https://localhost/',
      ' //evil.com/x',
      'http:evil.com',
      '//evil.com'
    ]
    for (const source of sources) {
      let origin
      try {
        origin = buildURL(source, 'http://localhost').origin
      } catch (err) {
        continue
      }
      expect(origin, source).to.equal('http://localhost')
    }
  })

  it('should allow same origin absolute sources', () => {
    expect(buildURL('http://localhost/hi', 'http://localhost').href).to.equal('http://localhost/hi')
  })
})

describe('Hardening: utils', () => {
  const utils = require('../lib/utils')

  it('should not forward hop-by-hop, framing and pseudo request headers', () => {
    const headers = utils.buildRequestHeaders({
      ':method': 'GET',
      ':path': '/',
      host: 'gateway',
      connection: 'upgrade, x-custom',
      'keep-alive': 'timeout=5',
      'proxy-connection': 'keep-alive',
      'proxy-authorization': 'Basic Zm9v',
      te: 'trailers',
      trailer: 'x-checksum',
      'transfer-encoding': 'chunked',
      Upgrade: 'websocket',
      'http2-settings': 'AAMAAABkAAQCAAAAAAIAAAAA',
      expect: '100-continue',
      'Content-Length': '10',
      'x-custom': 'kept',
      Authorization: 'Bearer token',
      cookie: 'a=1'
    })

    expect(headers).to.deep.equal({
      host: 'gateway',
      'x-custom': 'kept',
      authorization: 'Bearer token',
      cookie: 'a=1'
    })
  })

  it('should not let clients remove headers through the Connection header', () => {
    const headers = utils.buildRequestHeaders({ connection: 'x-user-id', 'x-user-id': '1' })

    expect(headers).to.deep.equal({ 'x-user-id': '1' })
  })

  it('should strip hop-by-hop response headers, including the ones nominated by Connection', () => {
    const headers = utils.stripHttp1ConnectionHeaders({
      Connection: 'Keep-Alive, X-Internal , , constructor',
      'Keep-Alive': 'timeout=5',
      'X-Internal': 'secret',
      Trailer: 'x-checksum',
      'Proxy-Authenticate': 'Basic',
      'Transfer-Encoding': 'chunked',
      'Content-Type': 'text/plain',
      'set-cookie': ['a=1', 'b=2']
    })

    expect(headers).to.deep.equal({ 'content-type': 'text/plain', 'set-cookie': ['a=1', 'b=2'] })
  })

  it('should preserve values of mixed case response headers', () => {
    expect(utils.stripHttp1ConnectionHeaders({ 'X-Mixed': 'Case', connection: 'close' })).to.deep.equal({ 'x-mixed': 'Case' })
  })

  it('should skip empty header values when copying', () => {
    const set = {}
    utils.copyHeaders({ a: '1', b: undefined, c: null, ':status': 200 }, { setHeader: (name, value) => { set[name] = value } })

    expect(set).to.deep.equal({ a: '1' })
  })

  it('should detect form urlencoded content type', () => {
    expect(utils.isFormUrlEncoded('application/x-www-form-urlencoded')).to.equal(true)
    expect(utils.isFormUrlEncoded('application/x-www-form-urlencoded; charset=UTF-8')).to.equal(true)
    expect(utils.isFormUrlEncoded('Application/X-WWW-Form-Urlencoded ;charset=utf-8')).to.equal(true)
    expect(utils.isFormUrlEncoded('application/x-www-form-urlencoded-not')).to.equal(false)
    expect(utils.isFormUrlEncoded('application/json')).to.equal(false)
    expect(utils.isFormUrlEncoded(undefined)).to.equal(false)
  })

  it('should serialize form urlencoded payloads', () => {
    expect(utils.toFormUrlEncoded({ a: '1', b: ['2', '3'], c: { d: 'x y', e: { f: true } }, g: null, h: [{ i: 1 }] }))
      .to.equal('a=1&b=2&b=3&c%5Bd%5D=x+y&c%5Be%5D%5Bf%5D=true&g=&h%5B0%5D%5Bi%5D=1')
  })

  it('should not overflow on cyclic form payloads', () => {
    const body = { a: 1 }
    body.self = body

    expect(utils.toFormUrlEncoded(body)).to.be.a('string')
  })

  it('should detect empty plain objects', () => {
    expect(utils.isEmptyPlainObject({})).to.equal(true)
    expect(utils.isEmptyPlainObject(Object.create(null))).to.equal(true)
    expect(utils.isEmptyPlainObject({ a: 1 })).to.equal(false)
    expect(utils.isEmptyPlainObject([])).to.equal(false)
    expect(utils.isEmptyPlainObject(new Date())).to.equal(false)
  })

  it('should validate content-length values', () => {
    expect(utils.isValidContentLength('0')).to.equal(true)
    expect(utils.isValidContentLength('1024')).to.equal(true)
    expect(utils.isValidContentLength('10, 10')).to.equal(false)
    expect(utils.isValidContentLength('-1')).to.equal(false)
    expect(utils.isValidContentLength('0x10')).to.equal(false)
    expect(utils.isValidContentLength('')).to.equal(false)
    expect(utils.isValidContentLength(undefined)).to.equal(false)
  })
})

describe('Hardening: invalid targets do not crash the process', () => {
  let gateway, port, proxy, close

  before(async () => {
    ({ proxy, close } = fastProxy({}))
    gateway = http.createServer((req, res) => proxy(req, res, req.url, {}))
    port = await listen(gateway)
  })

  after(async () => {
    close()
    await closeServer(gateway)
  })

  it('should 400 on unsupported protocol (absolute-form request, no base)', async () => {
    for (const target of ['ftp://example.com/x', 'file:///etc/passwd', 'ws://example.com/x']) {
      const res = await raw(port, `GET ${target} HTTP/1.1\r\nHost: a\r\nConnection: close\r\n\r\n`)
      expect(res.status, target).to.equal(400)
    }
  })

  it('should 400 on relative source when base is not set', async () => {
    const res = await raw(port, 'GET /hi HTTP/1.1\r\nHost: a\r\nConnection: close\r\n\r\n')
    expect(res.status).to.equal(400)
  })
})

describe('Hardening: route prefix escape', () => {
  let gateway, service, port, proxy, close

  before(async () => {
    service = http.createServer((req, res) => res.end(req.url))
    const servicePort = await listen(service);
    ({ proxy, close } = fastProxy({ base: 'http://127.0.0.1:' + servicePort }))
    gateway = http.createServer((req, res) => {
      if (!req.url.startsWith('/public/')) {
        res.statusCode = 403
        res.end()
      } else {
        proxy(req, res, req.url, {})
      }
    })
    port = await listen(gateway)
  })

  after(async () => {
    close()
    await closeServer(gateway)
    await closeServer(service)
  })

  it('should not forward requests escaping the routed prefix', async () => {
    const targets = [
      '/public/../admin',
      '/public/%2e%2e/admin',
      '/public/.%2E/admin',
      '/public/x/..\\..\\admin',
      '/public/./../admin',
      '/public/x/../../admin?a=1'
    ]
    for (const target of targets) {
      const res = await raw(port, `GET ${target} HTTP/1.1\r\nHost: a\r\nConnection: close\r\n\r\n`)
      expect(res.status, target).to.equal(400)
    }
  })

  it('should forward regular requests', async () => {
    const res = await raw(port, 'GET /public/..hidden/.x?path=/../y HTTP/1.1\r\nHost: a\r\nConnection: close\r\n\r\n')
    expect(res.status).to.equal(200)
    expect(res.body).to.equal('/public/..hidden/.x?path=/../y')
  })
})

describe('Hardening: request headers and framing (HTTP/1 source)', () => {
  let gateway, parsedGateway, remote, port, parsedPort, proxy, close

  before(async () => {
    remote = wireServer()
    const remotePort = await listen(remote.server);
    ({ proxy, close } = fastProxy({ base: 'http://127.0.0.1:' + remotePort }))

    gateway = http.createServer((req, res) => proxy(req, res, req.url, {}))
    port = await listen(gateway)

    const parsers = [bodyParser.json(), bodyParser.urlencoded({ extended: true }), bodyParser.raw(), bodyParser.text()]
    parsedGateway = http.createServer((req, res) => {
      let i = 0
      const next = () => i < parsers.length ? parsers[i++](req, res, next) : proxy(req, res, req.url, {})
      next()
    })
    parsedPort = await listen(parsedGateway)
  })

  after(async () => {
    close()
    await closeServer(gateway)
    await closeServer(parsedGateway)
    await closeServer(remote.server)
  })

  async function send (gatewayPort, payload) {
    remote.wire = ''
    const res = await raw(gatewayPort, payload)
    const [head, ...body] = remote.wire.split('\r\n\r\n')

    return { res, head: head.toLowerCase(), body: body.join('\r\n\r\n'), wire: remote.wire }
  }

  it('should not forward hop-by-hop request headers', async () => {
    const { res, head } = await send(port, 'GET /x HTTP/1.1\r\nHost: a\r\nConnection: close, x-secret\r\nKeep-Alive: timeout=1\r\nTE: trailers\r\nTrailer: x-sum\r\nProxy-Authorization: Basic Zm9v\r\nProxy-Connection: close\r\nX-Secret: kept\r\n\r\n')

    expect(res.status).to.equal(200)
    expect(head).to.include('connection: keep-alive')
    expect(head).to.not.include('connection: close')
    expect(head).to.not.include('timeout=1')
    expect(head).to.not.include('te:')
    expect(head).to.not.include('trailer:')
    expect(head).to.not.include('proxy-authorization')
    expect(head).to.not.include('proxy-connection')
    expect(head).to.include('x-secret: kept')
  })

  it('should not forward upgrade requests to the remote', async () => {
    const { res, head } = await send(port, 'GET /x HTTP/1.1\r\nHost: a\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n')

    expect(res.status).to.equal(200)
    expect(head).to.not.include('upgrade')
  })

  it('should not forward Expect header', async () => {
    const { res, head, body } = await send(port, 'POST /x HTTP/1.1\r\nHost: a\r\nConnection: close\r\nExpect: 100-continue\r\nContent-Length: 5\r\n\r\nhello')

    expect(res.data).to.include('200 OK')
    expect(head).to.not.include('expect')
    expect(body).to.equal('hello')
  })

  it('should ignore payload and framing headers on GET', async () => {
    const { res, head, body } = await send(port, 'GET /x HTTP/1.1\r\nHost: a\r\nConnection: close\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n')

    expect(res.status).to.equal(200)
    expect(head).to.not.include('transfer-encoding')
    expect(head).to.not.include('content-length')
    expect(body).to.equal('')
  })

  it('should stream content-length delimited payloads', async () => {
    const { res, head, body } = await send(port, 'DELETE /x HTTP/1.1\r\nHost: a\r\nConnection: close\r\nContent-Length: 5\r\n\r\nhello')

    expect(res.status).to.equal(200)
    expect(head).to.include('content-length: 5')
    expect(head).to.not.include('transfer-encoding')
    expect(body).to.equal('hello')
  })

  it('should re-frame chunked payloads', async () => {
    for (const method of ['POST', 'DELETE', 'OPTIONS', 'PATCH']) {
      const { res, head, body } = await send(port, `${method} /x HTTP/1.1\r\nHost: a\r\nConnection: close\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nhel\r\n2\r\nlo\r\n0\r\n\r\n`)

      expect(res.status, method).to.equal(200)
      expect(head, method).to.include('transfer-encoding: chunked')
      expect(head, method).to.not.include('content-length')
      expect(body.replace(/\r\n/g, '|'), method).to.match(/^(?:[0-9a-f]+\|[a-z]+\|)+0\|\|$/)
      expect(body.replace(/[0-9a-f]+\r\n|\r\n/g, ''), method).to.equal('hello')
    }
  })

  it('should not send a payload for requests without one', async () => {
    const post = await send(port, 'POST /x HTTP/1.1\r\nHost: a\r\nConnection: close\r\n\r\n')
    expect(post.res.status).to.equal(200)
    expect(post.head).to.include('content-length: 0')
    expect(post.head).to.not.include('transfer-encoding')
    expect(post.body).to.equal('')

    const del = await send(port, 'DELETE /x HTTP/1.1\r\nHost: a\r\nConnection: close\r\n\r\n')
    expect(del.res.status).to.equal(200)
    expect(del.head).to.not.include('transfer-encoding')
    expect(del.body).to.equal('')
  })

  it('should never send both content-length and transfer-encoding (parsed chunked payload)', async () => {
    const { res, head, body } = await send(parsedPort, 'POST /x HTTP/1.1\r\nHost: a\r\nConnection: close\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\n\r\n7\r\n{"a":1}\r\n0\r\n\r\n')

    expect(res.status).to.equal(200)
    expect(head).to.include('content-length: 7')
    expect(head).to.not.include('transfer-encoding')
    expect(body).to.equal('{"a":1}')
  })

  it('should forward form urlencoded payloads having media type parameters', async () => {
    const payload = 'a=1&b=2'
    const { head, body } = await send(parsedPort, `POST /x HTTP/1.1\r\nHost: a\r\nConnection: close\r\nContent-Type: application/x-www-form-urlencoded; charset=UTF-8\r\nContent-Length: ${payload.length}\r\n\r\n${payload}`)

    expect(head).to.include('content-type: application/x-www-form-urlencoded; charset=utf-8')
    expect(body).to.equal('a=1&b=2')
  })

  it('should forward nested form urlencoded payloads', async () => {
    const payload = 'a[b]=1&c=2&c=3'
    const { body } = await send(parsedPort, `POST /x HTTP/1.1\r\nHost: a\r\nConnection: close\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: ${payload.length}\r\n\r\n${payload}`)

    expect(decodeURIComponent(body)).to.equal('a[b]=1&c=2&c=3')
  })

  it('should forward binary payloads untouched', async () => {
    const { head, body } = await send(parsedPort, 'POST /x HTTP/1.1\r\nHost: a\r\nConnection: close\r\nContent-Type: application/octet-stream\r\nContent-Length: 4\r\n\r\n\x00\x01\xfe\xff')

    expect(head).to.include('content-length: 4')
    expect(head).to.include('content-type: application/octet-stream')
    expect(body).to.equal('\x00\x01\xfe\xff')
  })

  it('should stream payloads the body parsers did not handle', async () => {
    const { head, body } = await send(parsedPort, 'POST /x HTTP/1.1\r\nHost: a\r\nConnection: close\r\nContent-Type: text/xml\r\nContent-Length: 8\r\n\r\n<a>1</a>')

    expect(head).to.include('content-length: 8')
    expect(body).to.equal('<a>1</a>')
  })

  it('should forward parsed empty JSON objects', async () => {
    const { head, body } = await send(parsedPort, 'POST /x HTTP/1.1\r\nHost: a\r\nConnection: close\r\nContent-Type: application/json\r\nContent-Length: 2\r\n\r\n{}')

    expect(head).to.include('content-length: 2')
    expect(body).to.equal('{}')
  })

  it('should forward parsed text payloads', async () => {
    const { head, body } = await send(parsedPort, 'POST /x HTTP/1.1\r\nHost: a\r\nConnection: close\r\nContent-Type: text/plain\r\nContent-Length: 6\r\n\r\nh\xc3\xa9llo')

    expect(head).to.include('content-length: 6')
    expect(body).to.equal('h\xc3\xa9llo')
  })
})

describe('Hardening: request body shapes', () => {
  let gateway, remote, port, proxy, close, prepare, proxyOpts

  before(async () => {
    remote = wireServer()
    const remotePort = await listen(remote.server);
    ({ proxy, close } = fastProxy({ base: 'http://127.0.0.1:' + remotePort }))

    gateway = http.createServer((req, res) => {
      prepare(req, () => proxy(req, res, req.url, proxyOpts))
    })
    port = await listen(gateway)
  })

  after(async () => {
    close()
    await closeServer(gateway)
    await closeServer(remote.server)
  })

  async function send (prepareFn, opts = {}) {
    remote.wire = ''
    prepare = prepareFn
    proxyOpts = opts
    const res = await raw(port, 'POST /x HTTP/1.1\r\nHost: a\r\nConnection: close\r\nContent-Length: 5\r\n\r\nhello')
    const [head, ...body] = remote.wire.split('\r\n\r\n')

    return { res, head: head.toLowerCase(), body: body.join('\r\n\r\n') }
  }

  it('should forward typed arrays', async () => {
    const { head, body } = await send((req, next) => {
      req.body = new Uint8Array([104, 105])
      next()
    })

    expect(head).to.include('content-length: 2')
    expect(body).to.equal('hi')
  })

  it('should forward empty strings', async () => {
    const { head, body } = await send((req, next) => {
      req.body = ''
      next()
    })

    expect(head).to.include('content-length: 0')
    expect(body).to.equal('')
  })

  it('should forward JSON primitives', async () => {
    const { head, body } = await send((req, next) => {
      req.body = 0
      next()
    })

    expect(head).to.include('content-length: 1')
    expect(head).to.include('content-type: application/json')
    expect(body).to.equal('0')
  })

  it('should forward custom streams using chunked encoding when the length is unknown', async () => {
    const { head, body } = await send((req, next) => {
      delete req.headers['content-length']
      req.body = new PassThrough()
      req.body.end('custom')
      next()
    })

    expect(head).to.include('transfer-encoding: chunked')
    expect(head).to.not.include('content-length')
    expect(body).to.equal('6\r\ncustom\r\n0\r\n\r\n')
  })

  it('should not send a payload when the request was already consumed', async () => {
    const { res, head, body } = await send((req, next) => {
      req.resume()
      req.on('end', () => setImmediate(next))
    })

    expect(res.status).to.equal(200)
    expect(head).to.include('content-length: 0')
    expect(body).to.equal('')
  })

  it('should keep the request framed when a hook removes the framing headers', async () => {
    const { head, body } = await send((req, next) => next(), {
      rewriteRequestHeaders: (req, headers) => {
        delete headers['content-length']

        return headers
      }
    })

    expect(head).to.include('transfer-encoding: chunked')
    expect(body).to.equal('5\r\nhello\r\n0\r\n\r\n')
  })

  it('should respect framing headers set by a hook using a different case', async () => {
    const { head, body } = await send((req, next) => next(), {
      rewriteRequestHeaders: (req, headers) => {
        delete headers['content-length']
        headers['Content-Length'] = '5'

        return headers
      }
    })

    expect(head).to.include('content-length: 5')
    expect(head).to.not.include('transfer-encoding')
    expect(body).to.equal('hello')
  })

  it('should tolerate hooks returning nothing', async () => {
    const { res, body } = await send((req, next) => next(), {
      rewriteRequestHeaders: () => {},
      rewriteHeaders: () => {}
    })

    expect(res.status).to.equal(200)
    expect(body).to.equal('hello')
  })

  it('should 400 when the request can not be represented to the remote', async () => {
    const { res } = await send((req, next) => next(), {
      rewriteRequestHeaders: (req, headers) => {
        headers['x-invalid'] = 'line\r\nbreak'

        return headers
      }
    })

    expect(res.status).to.equal(400)
    expect(remote.wire).to.equal('')
  })
})

describe('Hardening: request smuggling (HTTP/2 source)', () => {
  let gateway, remote, client, proxy, close

  before(async () => {
    remote = wireServer('HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: keep-alive\r\nKeep-Alive: timeout=5\r\nX-Remote: 1\r\n\r\nok')
    const remotePort = await listen(remote.server);
    ({ proxy, close } = fastProxy({ base: 'http://127.0.0.1:' + remotePort }))

    gateway = http2.createServer((req, res) => proxy(req, res, req.url, {}))
    const port = await listen(gateway)
    client = http2.connect('http://127.0.0.1:' + port)
  })

  after(async () => {
    close()
    await new Promise(resolve => client.close(resolve))
    await closeServer(gateway)
    await closeServer(remote.server)
  })

  function send (headers, payload) {
    remote.wire = ''

    return new Promise((resolve, reject) => {
      const req = client.request(headers, { endStream: payload === undefined })
      let status
      let resHeaders
      let body = ''
      req.on('response', h => {
        status = h[':status']
        resHeaders = h
      })
      req.on('data', chunk => { body += chunk })
      req.on('end', () => resolve({ status, headers: resHeaders, body, wire: remote.wire }))
      req.on('error', reject)
      if (payload !== undefined) req.end(payload)
    })
  }

  it('should frame payloads having no content-length', async () => {
    const smuggled = 'GET /admin HTTP/1.1\r\nHost: internal\r\n\r\n'
    for (const method of ['DELETE', 'OPTIONS', 'POST', 'PUT']) {
      const res = await send({ ':method': method, ':path': '/x' }, smuggled)
      const [head, ...rest] = res.wire.split('\r\n\r\n')
      const body = rest.join('\r\n\r\n')

      expect(res.status, method).to.equal(200)
      expect(head.toLowerCase(), method).to.include('transfer-encoding: chunked')
      // the payload must be chunk encoded, not written as a second request
      expect(body.startsWith(smuggled.length.toString(16) + '\r\n' + smuggled), method).to.equal(true)
      expect(body.endsWith('\r\n0\r\n\r\n'), method).to.equal(true)
    }
  })

  it('should forward content-length delimited payloads', async () => {
    const res = await send({ ':method': 'DELETE', ':path': '/x', 'content-length': '5' }, 'hello')
    const [head, body] = res.wire.split('\r\n\r\n')

    expect(res.status).to.equal(200)
    expect(head.toLowerCase()).to.include('content-length: 5')
    expect(head.toLowerCase()).to.not.include('transfer-encoding')
    expect(body).to.equal('hello')
  })

  it('should build host from :authority and strip connection headers from the response', async () => {
    const res = await send({ ':method': 'GET', ':path': '/x?a=1' })

    expect(res.status).to.equal(200)
    expect(res.body).to.equal('ok')
    expect(res.headers['x-remote']).to.equal('1')
    expect(res.headers.connection).to.equal(undefined)
    expect(res.headers['keep-alive']).to.equal(undefined)
    expect(res.wire).to.match(/^GET \/x\?a=1 HTTP\/1\.1\r\n/)
    expect(res.wire.toLowerCase()).to.match(/x-forwarded-host: 127\.0\.0\.1:\d+/)
  })
})

describe('Hardening: remote failures', () => {
  let gateway, port, proxy, close, remote, remotePort, behavior, terminated

  before(async () => {
    remote = track(net.createServer(socket => {
      socket.on('error', () => {})
      socket.once('data', () => behavior(socket))
    }))
    remotePort = await listen(remote);
    ({ proxy, close } = fastProxy({ base: 'http://127.0.0.1:' + remotePort }))

    gateway = http.createServer((req, res) => proxy(req, res, req.url, {
      request: { timeout: 200 },
      onClientConnectionTerminated: () => { terminated++ }
    }))
    port = await listen(gateway)
  })

  after(async () => {
    close()
    await closeServer(gateway)
    await closeServer(remote)
  })

  const GET = 'GET /x HTTP/1.1\r\nHost: a\r\n\r\n'

  it('should not corrupt the response when the remote fails after sending the headers', async () => {
    terminated = 0
    behavior = socket => {
      socket.write('HTTP/1.1 200 OK\r\nContent-Length: 1000\r\n\r\npartial-body')
      setTimeout(() => socket.destroy(), 50)
    }
    const res = await raw(port, GET, 2000)

    expect(res.status).to.equal(200)
    expect(res.body).to.equal('partial-body')
    // the truncated response must be signaled by terminating the connection
    expect(res.closedByPeer).to.equal(true)
    expect(terminated).to.equal(0)
  })

  it('should not corrupt the response when the remote times out after sending the headers', async () => {
    behavior = socket => {
      socket.write('HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n')
    }
    const res = await raw(port, GET, 2000)

    expect(res.status).to.equal(200)
    expect(res.body).to.equal('5\r\nhello\r\n')
    expect(res.closedByPeer).to.equal(true)
  })

  it('should 504 when the remote does not respond in time', async () => {
    behavior = () => {}
    const res = await raw(port, GET.replace('\r\n\r\n', '\r\nConnection: close\r\n\r\n'), 2000)

    expect(res.status).to.equal(504)
    expect(res.body).to.equal('Gateway Timeout')
  })

  it('should 502 on invalid status code', async () => {
    for (const statusLine of ['HTTP/1.1 099 Weird', 'HTTP/1.1 000 Zero']) {
      behavior = socket => socket.end(statusLine + '\r\nContent-Length: 2\r\nX-Remote: 1\r\n\r\nhi')
      const res = await raw(port, GET.replace('\r\n\r\n', '\r\nConnection: close\r\n\r\n'), 2000)

      expect(res.status, statusLine).to.equal(502)
      expect(res.body, statusLine).to.equal('Bad Gateway')
      expect(res.data.toLowerCase(), statusLine).to.not.include('x-remote')
    }
  })

  it('should 502 on malformed response', async () => {
    behavior = socket => socket.end('NOT HTTP\r\n\r\n')
    const res = await raw(port, GET.replace('\r\n\r\n', '\r\nConnection: close\r\n\r\n'), 2000)

    expect(res.status).to.equal(502)
    expect(res.body).to.equal('Bad Gateway')
  })

  it('should 502 instead of hanging when the remote switches protocols', async () => {
    behavior = socket => socket.write('HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n')
    const res = await raw(port, GET.replace('\r\n\r\n', '\r\nConnection: close\r\n\r\n'), 2000)

    expect(res.status).to.equal(502)
  })

  it('should 503 when the remote is not available, also for requests having a payload', async () => {
    const { proxy, close } = fastProxy({ base: 'http://127.0.0.1:1' })
    const gateway = http.createServer((req, res) => proxy(req, res, req.url, {}))
    const port = await listen(gateway)

    const res = await raw(port, 'POST /x HTTP/1.1\r\nHost: a\r\nConnection: close\r\nContent-Length: 5\r\n\r\nhello', 2000)
    expect(res.status).to.equal(503)
    expect(res.body).to.equal('Service Unavailable')

    close()
    await closeServer(gateway)
  })
})

describe('Hardening: client connection terminated', () => {
  let gateway, port, proxy, close, remote, remoteRequests, remoteClosed, terminated, hook

  before(async () => {
    remote = http.createServer((req, res) => {
      remoteRequests++
      req.socket.once('close', () => { remoteClosed++ })
      if (req.url === '/slow') {
        // never responds
      } else {
        res.end(Buffer.alloc(1024 * 1024))
      }
    })
    const remotePort = await listen(remote);
    ({ proxy, close } = fastProxy({ base: 'http://127.0.0.1:' + remotePort }))

    gateway = http.createServer((req, res) => {
      const forward = () => proxy(req, res, req.url, {
        onClientConnectionTerminated: (res, err, response) => {
          terminated.push({ err, response })
          if (hook) hook(response)
        }
      })

      if (req.url === '/late') {
        // the client is gone before the request is forwarded
        res.on('close', forward)
      } else {
        forward()
      }
    })
    port = await listen(gateway)
  })

  after(async () => {
    close()
    await closeServer(gateway)
    await closeServer(remote)
  })

  function reset () {
    remoteRequests = 0
    remoteClosed = 0
    terminated = []
    hook = null
  }

  it('should abort the remote request when the client goes away', async () => {
    reset()
    await raw(port, 'GET /slow HTTP/1.1\r\nHost: a\r\n\r\n', 100)
    await sleep(200)

    expect(remoteRequests).to.equal(1)
    expect(remoteClosed).to.equal(1)
    expect(terminated.length).to.equal(1)
    expect(terminated[0].err.code).to.equal('ECONNRESET')
    expect(terminated[0].response).to.equal(undefined)
  })

  it('should release the remote connection when the response is not consumed', async () => {
    reset()
    await raw(port, 'GET /late HTTP/1.1\r\nHost: a\r\n\r\n', 50)
    await sleep(300)

    expect(remoteRequests).to.equal(1)
    expect(terminated.length).to.equal(1)
    expect(terminated[0].err).to.equal(null)
    expect(terminated[0].response.statusCode).to.equal(200)
    expect(terminated[0].response.stream.destroyed).to.equal(true)
    expect(remoteClosed).to.equal(1)
  })

  it('should not destroy the response when the hook consumes it', async () => {
    reset()
    let received = 0
    let ended = false
    hook = response => {
      response.stream.on('data', chunk => { received += chunk.length })
      response.stream.on('end', () => { ended = true })
    }
    await raw(port, 'GET /late HTTP/1.1\r\nHost: a\r\n\r\n', 50)
    await sleep(300)

    expect(terminated.length).to.equal(1)
    expect(ended).to.equal(true)
    expect(received).to.equal(1024 * 1024)
  })
})

describe('Hardening: custom request clients', () => {
  // minimal http client double
  function fakeClient (handler) {
    const calls = []

    return {
      calls,
      request (options) {
        calls.push(options)
        const req = new EventEmitter()
        req.end = () => setImmediate(() => handler(req, options))
        req.destroy = () => {}

        return req
      }
    }
  }

  async function run (client, base, requestLine = 'GET /x HTTP/1.1') {
    const { proxy, close } = fastProxy({ base, requests: { http: client, https: client } })
    const gateway = http.createServer((req, res) => proxy(req, res, req.url, {}))
    const port = await listen(gateway)
    const res = await raw(port, requestLine + '\r\nHost: a\r\nConnection: close\r\n\r\n', 2000)
    close()
    await closeServer(gateway)

    return res
  }

  function respond (req, statusCode, headers, body = '') {
    const stream = new PassThrough()
    stream.statusCode = statusCode
    stream.headers = headers
    req.emit('response', stream)
    stream.end(body)
  }

  it('should connect to IPv6 literals without brackets, keeping them in the Host header', async () => {
    const client = fakeClient(req => respond(req, 200, {}, 'ok'))
    const res = await run(client, 'http://[::1]:3000')

    expect(res.status).to.equal(200)
    expect(client.calls[0].hostname).to.equal('::1')
    expect(client.calls[0].port).to.equal('3000')
    expect(client.calls[0].headers.host).to.equal('[::1]:3000')
  })

  it('should map default ports and hostnames', async () => {
    const client = fakeClient(req => respond(req, 200, {}, 'ok'))
    await run(client, 'https://example.com')

    expect(client.calls[0].hostname).to.equal('example.com')
    expect(client.calls[0].port).to.equal('')
    expect(client.calls[0].headers.host).to.equal('example.com')
    expect(client.calls[0].path).to.equal('/x')
  })

  it('should forward mixed case response headers', async () => {
    const client = fakeClient(req => respond(req, 201, { 'X-Mixed': 'Case', Connection: 'x-hop', 'X-Hop': '1', 'x-undefined': undefined }, 'ok'))
    const res = await run(client, 'http://example.com')

    expect(res.status).to.equal(201)
    expect(res.data).to.include('x-mixed: Case')
    expect(res.data.toLowerCase()).to.not.include('x-hop')
    expect(res.data.toLowerCase()).to.not.include('x-undefined')
    expect(res.body).to.equal('2\r\nok\r\n0\r\n\r\n')
  })

  it('should 502 on response headers that can not be sent to the client', async () => {
    const client = fakeClient(req => respond(req, 200, { 'x-ok': '1', 'x-invalid': 'line\r\nbreak' }, 'ok'))
    const res = await run(client, 'http://example.com')

    expect(res.status).to.equal(502)
    expect(res.body).to.equal('Bad Gateway')
    expect(res.data.toLowerCase()).to.not.include('x-ok')
  })

  it('should 502 on non numeric status codes', async () => {
    const client = fakeClient(req => respond(req, '200 OK', {}, 'ok'))
    const res = await run(client, 'http://example.com')

    expect(res.status).to.equal(502)
  })

  it('should map error codes to status codes', async () => {
    const codes = { ECONNREFUSED: 503, ECONNRESET: 504, ETIMEDOUT: 504, ENOTFOUND: 502, EPIPE: 502, undefined: 502 }
    for (const code of Object.keys(codes)) {
      const client = fakeClient(req => {
        const err = new Error('sensitive internal details')
        if (code !== 'undefined') err.code = code
        req.emit('error', err)
      })
      const res = await run(client, 'http://example.com')

      expect(res.status, code).to.equal(codes[code])
      expect(res.data, code).to.not.include('sensitive')
    }
  })

  it('should ignore errors and responses received after the request was settled', async () => {
    let lateResponse
    const client = fakeClient(req => {
      req.emit('error', Object.assign(new Error('first'), { code: 'ECONNREFUSED' }))
      req.emit('error', Object.assign(new Error('second'), { code: 'ECONNRESET' }))
      lateResponse = new PassThrough()
      lateResponse.statusCode = 200
      lateResponse.headers = {}
      req.emit('response', lateResponse)
    })
    const res = await run(client, 'http://example.com')

    expect(res.status).to.equal(503)
    expect(res.body).to.equal('Service Unavailable')
    expect(lateResponse.destroyed).to.equal(true)
  })

  it('should abort using abort() when the client does not support destroy()', async () => {
    let aborted = false
    const client = {
      request () {
        const req = new EventEmitter()
        req.end = () => setImmediate(() => req.emit('timeout'))
        req.abort = () => {
          aborted = true
          req.emit('error', Object.assign(new Error('socket hang up'), { code: 'ECONNRESET' }))
        }

        return req
      }
    }
    const res = await run(client, 'http://example.com')

    expect(aborted).to.equal(true)
    expect(res.status).to.equal(504)
  })

  it('should not pass proxy options down to the agents', () => {
    const { Agent } = http
    const seen = []
    http.Agent = function (options) {
      seen.push(options)

      return new Agent(options)
    }
    try {
      fastProxy({ base: 'http://example.com', cacheURLs: 10, requests: {}, maxSockets: 5 }).close()
    } finally {
      http.Agent = Agent
    }

    expect(seen[0]).to.deep.equal({ keepAlive: true, keepAliveMsecs: 60000, maxSockets: 5, maxFreeSockets: 2048 })
  })
})

describe('Hardening: query string and URL cache', () => {
  let gateway, service, port, proxy, close, servicePort, handler

  before(async () => {
    service = http.createServer((req, res) => res.end(req.headers.host + req.url))
    servicePort = await listen(service);
    ({ proxy, close } = fastProxy({ base: 'http://127.0.0.1:' + servicePort }))
    gateway = http.createServer((req, res) => handler(req, res))
    port = await listen(gateway)
  })

  after(async () => {
    close()
    await closeServer(gateway)
    await closeServer(service)
  })

  const get = target => raw(port, `GET ${target} HTTP/1.1\r\nHost: a\r\nConnection: close\r\n\r\n`)

  it('should append the original query string to sources having none', async () => {
    handler = (req, res) => proxy(req, res, '/rewritten', {})

    expect((await get('/x?a=1&b=2')).body).to.equal(`127.0.0.1:${servicePort}/rewritten?a=1&b=2`)
    expect((await get('/x')).body).to.equal(`127.0.0.1:${servicePort}/rewritten`)
  })

  it('should not forward fragments', async () => {
    handler = (req, res) => {
      req.url = req.headers['x-url']
      proxy(req, res, '/rewritten', {})
    }
    const send = url => raw(port, `GET / HTTP/1.1\r\nHost: a\r\nX-Url: ${url}\r\nConnection: close\r\n\r\n`)

    expect((await send('/x?a=1#frag')).body).to.equal(`127.0.0.1:${servicePort}/rewritten?a=1`)
    expect((await send('/x#frag?a=1')).body).to.equal(`127.0.0.1:${servicePort}/rewritten`)
  })

  it('should prefer the source query string and the queryString option', async () => {
    handler = (req, res) => proxy(req, res, '/rewritten?c=3', {})
    expect((await get('/x?a=1')).body).to.equal(`127.0.0.1:${servicePort}/rewritten?c=3`)

    handler = (req, res) => proxy(req, res, '/rewritten?c=3', { queryString: 'd=4&e=5' })
    expect((await get('/x?a=1')).body).to.equal(`127.0.0.1:${servicePort}/rewritten?d=4&e=5`)
  })

  it('should not mix cached URLs of different bases', async () => {
    const other = http.createServer((req, res) => res.end('other' + req.url))
    const otherPort = await listen(other)
    const globalBase = 'http://127.0.0.1:' + servicePort
    const otherBase = 'http://127.0.0.1:' + otherPort

    // a request target crafted to look like the cache key of another base
    const crafted = otherBase.length + ':' + otherBase + '/x'
    handler = (req, res) => proxy(req, res, req.headers['x-source'], { base: req.headers['x-base'] })
    const send = (source, base) => raw(port, `GET / HTTP/1.1\r\nHost: a\r\nX-Source: ${source}\r\n${base ? 'X-Base: ' + base + '\r\n' : ''}Connection: close\r\n\r\n`)

    try {
      expect((await send(crafted)).body).to.equal(`127.0.0.1:${servicePort}/${crafted}`)
      expect((await send('/x', otherBase)).body).to.equal('other/x')
      expect((await send('/x')).body).to.equal(`127.0.0.1:${servicePort}/x`)
      expect((await send('/x', otherBase)).body).to.equal('other/x')
      // "base + source" concatenations that are equal as plain strings
      expect((await send('/x', globalBase + '/a')).body).to.equal(`127.0.0.1:${servicePort}/x`)
      expect((await send('/a/x', globalBase)).body).to.equal(`127.0.0.1:${servicePort}/a/x`)
      expect((await send('/x', globalBase + '/a')).body).to.equal(`127.0.0.1:${servicePort}/x`)
    } finally {
      await closeServer(other)
    }
  })
})
