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

#### cacheURLs
The number of parsed URLs that will be cached. Default: 100.
> Use value = `0` to disable the caching mechanism

#### requests.http and requests.https
Allows to optionally overwrite the internal `http` and `https` client agents implementation. Defaults: [`http`](https://nodejs.org/api/http.html#http_http) and [`https`](https://nodejs.org/api/https.html#https_https).

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
Replaces the original querystring of the request with what is specified.

## Related topics
- http-agent: https://nodejs.org/api/http.html#http_new_agent_options
- https-agent: https://nodejs.org/api/https.html#https_class_https_agent

## License
MIT
