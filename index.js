'use strict'

const pump = require('pump')
const lru = require('tiny-lru')
const Stream = require('stream')
const buildRequest = require('./lib/request')

const {
  buildRequestHeaders,
  copyHeaders,
  stripHttp1ConnectionHeaders,
  isValidContentLength,
  isFormUrlEncoded,
  isEmptyPlainObject,
  toFormUrlEncoded,
  buildURL,
  populateHeaders
} = require('./lib/utils')

const { createError } = buildRequest

function fastProxy (opts = {}) {
  const { request, close } = buildRequest({
    ...opts
  })

  const cache = getCacheStorage(opts.cacheURLs)
  const base = opts.base
  const baseCachePrefix = getCachePrefix(base)

  return {
    close,
    proxy (req, res, source, opts) {
      opts = opts || {}
      const reqOpts = opts.request || {}
      const onResponse = opts.onResponse
      const onClientConnectionTerminated = opts.onClientConnectionTerminated || onClientConnectionTerminatedNoOp
      const rewriteHeaders = opts.rewriteHeaders || rewriteHeadersNoOp
      const rewriteRequestHeaders = opts.rewriteRequestHeaders || rewriteRequestHeadersNoOp

      let url
      try {
        url = opts.base
          ? getReqUrl(source || req.url, cache, opts.base, getCachePrefix(opts.base))
          : getReqUrl(source || req.url, cache, base, baseCachePrefix)
      } catch (err) {
        sendError(res, 400, 'Bad Request')

        return
      }

      const reqHeaders = req.headers
      const sourceHttp2 = req.httpVersionMajor === 2

      // An intermediary that converts an HTTP/2 request to HTTP/1.1
      // MUST create a Host header field if one is not present in a request
      // by copying the value of the :authority pseudo-header field.
      // see: https://httpwg.org/specs/rfc7540.html
      const host = reqHeaders.host || (sourceHttp2 ? reqHeaders[':authority'] : undefined)
      if (!host) {
        // https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Host
        // @TODO: Should add performance-aware host header value validation(regex-based) as a further step?
        res.statusCode = 400
        res.end()

        return
      }

      let headers = buildRequestHeaders(reqHeaders)
      headers.host = url.host
      headers['x-forwarded-host'] = host

      let body = null
      let streaming = false
      // according to https://tools.ietf.org/html/rfc2616#section-4.3
      // proxy should ignore message body when it's a GET or HEAD request
      // when proxy this request, the message framing headers are not forwarded to make it a valid http request
      if (req.method !== 'GET' && req.method !== 'HEAD') {
        body = req.body
        if (body === undefined || body === null) {
          body = req
        } else if (body instanceof Stream) {
          // forwarded as is
        } else if (typeof body === 'string') {
          populateHeaders(headers, body, 'text/plain')
        } else if (Buffer.isBuffer(body)) {
          populateHeaders(headers, body, 'application/octet-stream')
        } else if (ArrayBuffer.isView(body)) {
          body = Buffer.from(body.buffer, body.byteOffset, body.byteLength)
          populateHeaders(headers, body, 'application/octet-stream')
        } else if (typeof body === 'object' && req.readableEnded === false && isEmptyPlainObject(body)) {
          // body parsers commonly assign an empty object as "req.body" when the
          // request payload was not parsed (e.g: unsupported content-type), in
          // such case the payload is still unread and has to be streamed
          body = req
        } else if (typeof body === 'object' && isFormUrlEncoded(headers['content-type'])) {
          body = toFormUrlEncoded(body)
          populateHeaders(headers, body, 'application/x-www-form-urlencoded')
        } else {
          body = JSON.stringify(body) || ''
          populateHeaders(headers, body, 'application/json')
        }

        if (body instanceof Stream) {
          // The framing of the remote request is explicitly defined here, it
          // must never be left to the http client defaults: a body written to
          // a request with neither "content-length" nor "transfer-encoding"
          // is sent unframed, and would be parsed as a second (smuggled)
          // request by the remote server.
          if (body === req && req.readableEnded === true) {
            // an already consumed request has nothing left to forward
            body = null
          } else if (reqHeaders['transfer-encoding'] !== undefined) {
            // the incoming server already decoded the chunked payload
            headers['transfer-encoding'] = 'chunked'
            streaming = true
          } else if (isValidContentLength(reqHeaders['content-length'])) {
            headers['content-length'] = reqHeaders['content-length']
            streaming = true
          } else if (body === req && !sourceHttp2) {
            // an HTTP/1 request with no framing headers has no payload
            body = null
          } else {
            headers['transfer-encoding'] = 'chunked'
            streaming = true
          }
        }
      }

      headers = rewriteRequestHeaders(req, headers) || headers
      if (streaming && !hasFramingHeaders(headers)) {
        headers['transfer-encoding'] = 'chunked'
      }

      const reqParams = {
        method: req.method,
        url,
        qs: getQueryString(url.search, req.url, opts),
        headers,
        body,
        request: reqOpts
      }

      let settled = false
      let abort
      try {
        abort = request(reqParams, (err, response) => {
          settled = true

          if (!res.socket || res.socket.destroyed || res.writableEnded) {
            onClientConnectionTerminated(res, err, response)

            // an unconsumed response would hold the remote connection forever
            if (response && response.stream && response.stream.readableFlowing === null) {
              response.stream.destroy()
            }

            return
          }

          if (err) {
            if (err.code === 'ECONNREFUSED') {
              sendError(res, 503, 'Service Unavailable')
            } else if (
              err.code === 'ECONNRESET' ||
              err.code === 'ETIMEDOUT' ||
              err.code === 'ESOCKETTIMEDOUT' ||
              err.code === 'UND_ERR_HEADERS_TIMEOUT' ||
              err.code === 'UND_ERR_BODY_TIMEOUT') {
              sendError(res, 504, 'Gateway Timeout')
            } else {
              sendError(res, 502, 'Bad Gateway')
            }

            return
          }

          // destructing response from remote
          const { headers, statusCode, stream } = response

          if (!isValidStatusCode(statusCode)) {
            stream.destroy()
            sendError(res, 502, 'Bad Gateway')

            return
          }

          // Strip hop-by-hop headers for all responses (HTTP/1.1 and HTTP/2).
          // Per RFC 7230 §6.1, hop-by-hop headers MUST NOT be forwarded by proxies.
          const safeHeaders = stripHttp1ConnectionHeaders(headers)
          const resHeaders = rewriteHeaders(safeHeaders) || safeHeaders

          try {
            copyHeaders(resHeaders, res)
          } catch (err) {
            // the remote response can't be represented to the client
            stream.destroy()
            removeHeaders(resHeaders, res)
            sendError(res, 502, 'Bad Gateway')

            return
          }

          // set origin response code
          res.statusCode = statusCode

          if (onResponse) {
            onResponse(req, res, stream)
          } else {
            pump(stream, res)
          }
        })
      } catch (err) {
        // the request can't be represented to the remote server:
        // invalid header name/value, invalid path characters...
        settled = true
        sendError(res, 400, 'Bad Request')

        return
      }

      if (!settled) {
        // do not keep the remote server busy when nobody is waiting for the response
        res.on('close', () => {
          if (!settled) {
            abort(createError('Client connection terminated', 'ECONNRESET'))
          }
        })
      }
    }
  }
}

function getQueryString (search, reqUrl, opts) {
  if (opts.queryString) {
    return '?' + new URLSearchParams(opts.queryString).toString()
  }

  if (search.length > 0) {
    return search
  }

  const queryIndex = reqUrl.indexOf('?')
  if (queryIndex > 0) {
    const hashIndex = reqUrl.indexOf('#')
    if (hashIndex === -1) {
      return reqUrl.slice(queryIndex)
    }
    if (hashIndex > queryIndex) {
      return reqUrl.slice(queryIndex, hashIndex)
    }
  }

  return ''
}

function hasFramingHeaders (headers) {
  if (headers['content-length'] !== undefined || headers['transfer-encoding'] !== undefined) {
    return true
  }

  // slow path: header names in a different case
  const keys = Object.keys(headers)
  let name
  for (let i = 0; i < keys.length; i++) {
    name = keys[i].toLowerCase()
    if (name === 'content-length' || name === 'transfer-encoding') {
      return true
    }
  }

  return false
}

function isValidStatusCode (statusCode) {
  return (statusCode | 0) === statusCode && statusCode >= 100 && statusCode <= 999
}

function sendError (res, statusCode, message) {
  if (res.headersSent) {
    // the response was already started, the only way to signal the failure is
    // to terminate the connection. Writing here would corrupt the payload.
    res.destroy()

    return
  }

  res.statusCode = statusCode
  res.end(message)
}

function removeHeaders (headers, res) {
  if (res.headersSent) {
    return
  }

  const headersKeys = Object.keys(headers)
  for (let i = 0; i < headersKeys.length; i++) {
    try {
      res.removeHeader(headersKeys[i])
    } catch (err) {
      // invalid header name, it was never set
    }
  }
}

function rewriteHeadersNoOp (headers) {
  return headers
}

function onClientConnectionTerminatedNoOp (_err, response) {

}

function rewriteRequestHeadersNoOp (req, headers) {
  return headers
}

function getCacheStorage (size) {
  if (size === 0) {
    return null
  }

  return lru(size || 100)
}

// The cache key must not allow two different (base, source) pairs to collide,
// the base is therefore length-prefixed. Sources used without a base are only
// cached when they are valid absolute URLs, which can't start with a digit.
function getCachePrefix (reqBase) {
  return reqBase ? reqBase.length + ':' + reqBase : ''
}

function getReqUrl (source, cache, reqBase, cachePrefix) {
  if (cache === null) {
    return toTarget(buildURL(source, reqBase))
  }

  const cacheKey = cachePrefix + source
  let url = cache.get(cacheKey)
  if (url === undefined) {
    url = toTarget(buildURL(source, reqBase))
    cache.set(cacheKey, url)
  }

  return url
}

// URL getters are computed on every access, the request target is cached as a
// plain object instead.
function toTarget (url) {
  const hostname = url.hostname

  return {
    protocol: url.protocol,
    host: url.host,
    // IPv6 literals: brackets belong to the URL syntax, not to the address
    hostname: hostname.charCodeAt(0) === 91 ? hostname.slice(1, -1) : hostname,
    port: url.port,
    pathname: url.pathname,
    search: url.search
  }
}

module.exports = fastProxy
module.exports.default = fastProxy
module.exports.fastProxy = fastProxy
