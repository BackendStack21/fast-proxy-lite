# fast-proxy-lite
Node.js framework agnostic library that enables you to forward an http request to another HTTP server. 
Supported proxy protocols: HTTP, HTTPS

> This library was initially forked from `fast-proxy`: https://github.com/fastify/fast-proxy

`fast-proxy-lite` powers: https://www.npmjs.com/package/fast-gateway 🚀 
## Install
```
npm i fast-proxy-lite
```

## Usage
The following examples describe how to use `fast-proxy-lite` with `restana`:

Gateway:
```js
const { proxy, close } = require('fast-proxy-lite')({
  base: 'http://127.0.0.1:3000'
  // options
})
const gateway = require('restana')()

gateway.all('/service/*', function (req, res) {
  proxy(req, res, req.url, {})
})

gateway.start(8080)
```

Remote service:
```js
const service = require('restana')()
service.get('/service/hi', (req, res) => res.send('Hello World!'))

service.start(3000)
```

Using imports:
```ts
import fastProxy from 'fast-proxy-lite'

const { proxy, close } = fastProxy({
  base: 'http://127.0.0.1:3000'
})
```

## Benchmarks
Please see: https://github.com/jkyberneees/nodejs-proxy-benchmarks

## API

### Options
#### `base`
Set the base URL for all the forwarded requests.
> When `base` is set, requests can only be forwarded to its origin (protocol + host + port). The path of `base` is not a restriction, see [Request target validation](#request-target-validation).

#### cacheURLs
The number of parsed URLs that will be cached. Default: 100.
> Use value = `0` to disable the caching mechanism

#### requests.http and requests.https
Allows to optionally overwrite the internal `http` and `https` client implementation. Defaults: [`http`](https://nodejs.org/api/http.html#http_http) and [`https`](https://nodejs.org/api/https.html#https_https).

For example, this could be used to add support for following redirects, like so:

```js
...
  requests: {
    http: require('follow-redirects/http'),
    https: require('follow-redirects/https')
  }
...
```

#### keepAliveMsecs
Defaults to 1 minute, passed down to [`http.Agent`][http-agent] and
[`https.Agent`][https-agent] instances.

#### maxSockets
Defaults to 2048 sockets, passed down to [`http.Agent`][http-agent] and
[`https.Agent`][https-agent] instances.

#### rejectUnauthorized
Defaults to `true`, passed down to [`https.Agent`][https-agent] instances.
This needs to be set to `false` to reply from https servers with
self-signed certificates.

#### Extended configurations
Other supported configurations in https://nodejs.org/api/http.html#http_new_agent_options can also be part of the `opts` object.

For example, `timeout` defines the maximum time (in milliseconds) the remote server connection can stay idle while a request is in flight:
```js
const { proxy, close } = require('fast-proxy-lite')({
  base: 'http://127.0.0.1:3000',
  timeout: 30000
})
```
> There is no timeout by default: a remote server that never responds keeps the client request open. Setting `timeout` here, or per request using `opts.request.timeout`, is strongly recommended.

### close
Optional _"on `close` resource release"_ strategy. You can link this to your application shutdown hook as an example.

### proxy(originReq, originRes, source, [opts])
Enables you to forward an http request to another HTTP server.
```js
proxy(
  originReq,                          // http.IncomingMessage 
  originRes,                          // http.ServerResponse
  req.url,                            // String -> remote URL + path or path if base was set
  {}                                  // Options described below
)
```
#### opts

##### base
Optionally indicates the base URL for the current request proxy. When used, the global `base` config is overwriten.  

##### onResponse(req, res, stream)
Called when an http response is received from the source.
The default behavior is `pump(stream, res)`, which will be disabled if the
option is specified.

##### onClientConnectionTerminated(res, err, response)
Called when the client HTTP connection to the proxy server unexpectedly terminates before the downstream service response is sent.  
```js
// internal implementation
if (!res.socket || res.socket.destroyed || res.writableEnded) {
  return onClientConnectionTerminated(res, err, response)
}
```
- The request to the remote server is aborted as soon as the client connection is terminated. In such case `err.code` is `ECONNRESET` and `response` is `undefined`.
- If the remote server responded anyway, `response` is defined and `err` is `null`. The response stream is destroyed right after the callback returns, unless the callback starts consuming it.

##### rewriteRequestHeaders(req, headers)
Called to rewrite the headers of the request, before them being sent to the downstream server. 
It must return the new headers object.

##### rewriteHeaders(headers)
Called to rewrite the headers of the response, before them being copied
over to the outer response.
It must return the new headers object.

##### request
Extended options supported by `http[s].request` method (https://nodejs.org/api/http.html#http_http_request_options_callback)  
> The following options are dynamically assigned: `method, port, path, hostname, headers, agent`.  

##### queryString
Replaces the original querystring of the request with what is specified. Accepts a string or an object.
> If `source` has no querystring and this option is not set, the querystring of the original request (`req.url`) is forwarded.

## Behavior

### Request body
`GET` and `HEAD` requests are always forwarded without a payload. For any other method, the payload is taken from `req.body` when a body parser already consumed the request:

| `req.body` | Forwarded payload | Default `content-type` |
|---|---|---|
| `undefined` / `null` | the request stream | - |
| `Stream` | the given stream | - |
| `string` | as is | `text/plain` |
| `Buffer` / typed array | as is | `application/octet-stream` |
| object, and the request `content-type` is `application/x-www-form-urlencoded` | URL encoded | `application/x-www-form-urlencoded` |
| anything else | JSON | `application/json` |

> An empty object (`{}`) on a request whose payload was not consumed is considered as "not parsed" (this is what `body-parser` assigns for content types it does not handle), the request stream is forwarded instead.

The `content-length`/`transfer-encoding` headers of the forwarded request are always (re)defined by the proxy, they are never copied blindly from the client request.

### Headers
- Request: hop-by-hop headers (`connection`, `keep-alive`, `proxy-connection`, `proxy-authorization`, `te`, `trailer`, `transfer-encoding`, `upgrade`, `http2-settings`) and `expect` are not forwarded. `host` is set to the remote host, the original value is forwarded as `x-forwarded-host`.
- Response: hop-by-hop headers (`connection`, `keep-alive`, `proxy-connection`, `proxy-authenticate`, `te`, `trailer`, `transfer-encoding`, `upgrade`, `http2-settings`), the headers nominated by the remote `connection` header, and `host` are not forwarded.

> Protocol upgrades (e.g: WebSockets) are not supported.

### Request target validation
The request is rejected with `400 Bad Request`, and nothing is sent to the remote server, when:
- The `host` header is missing.
- The target URL can't be parsed, or its protocol is not `http:` or `https:`.
- `base` is set and the target resolves to a different origin.
- The target path contains `.` or `..` segments (also in their `%2e` encoded form), backslashes, tabs or line breaks. URL parsers resolve those, the path sent to the remote server would be different than the one your router and access control logic have seen (e.g: `/public/../admin` matching a `/public/*` route).
- The request can't be represented as a valid HTTP request (e.g: invalid header values returned by `rewriteRequestHeaders`).

> When `base` is not set, `source` must be an absolute URL and no origin restriction applies. Never build it from untrusted input.

### Errors
| Condition | Response |
|---|---|
| Remote server refused the connection (`ECONNREFUSED`) | `503 Service Unavailable` |
| Remote server timeout or connection reset (`ETIMEDOUT`, `ECONNRESET`) | `504 Gateway Timeout` |
| Any other failure, including invalid responses | `502 Bad Gateway` |

If the remote server fails after the response headers were sent to the client, the client connection is terminated so the response is not mistaken with a complete one.

## Related topics
- http-agent: https://nodejs.org/api/http.html#http_new_agent_options
- https-agent: https://nodejs.org/api/https.html#https_class_https_agent

## License
MIT
