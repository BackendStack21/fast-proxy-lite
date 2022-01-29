'use strict'

const pump = require('pump')
const lru = require('tiny-lru')
const Stream = require('stream')
const buildRequest = require('./lib/request')

const {
  filterPseudoHeaders,
  copyHeaders,
  stripHttp1ConnectionHeaders,
  filterHeaders,
  buildURL,
  populateHeaders
} = require('./lib/utils')

function fastProxy (opts = {}) {
  const { request, close } = buildRequest({
    ...opts
  })

  const cache = getCacheStorage(opts.cacheURLs)
  const base = opts.base

  return {
    close,
    proxy (req, res, source, opts) {
      opts = opts || {}
      const reqOpts = opts.request || {}
      const onResponse = opts.onResponse
      const onClientConnectionTerminated = opts.onClientConnectionTerminated || onClientConnectionTerminatedNoOp
      const rewriteHeaders = opts.rewriteHeaders || rewriteHeadersNoOp
      const rewriteRequestHeaders = opts.rewriteRequestHeaders || rewriteRequestHeadersNoOp

      const url = getReqUrl(source || req.url, cache, base, opts)
      const sourceHttp2 = req.httpVersionMajor === 2
      let headers = { ...sourceHttp2 ? filterPseudoHeaders(req.headers) : req.headers }

      if (!headers.host) {
        // https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Host
        // @TODO: Should add performance-aware host header value validation(regex-based) as a further step?
        res.statusCode = 400
        res.end()

        return
      }

      headers['x-forwarded-host'] = headers.host
      headers.host = url.hostname
      if (url.port) {
        headers.host += `:${url.port}`
      }

      const qs = getQueryString(url.search, req.url, opts)

      let body = null
      // according to https://tools.ietf.org/html/rfc2616#section-4.3
      // proxy should ignore message body when it's a GET or HEAD request
      // when proxy this request, we should reset the content-length to make it a valid http request
      if (req.method === 'GET' || req.method === 'HEAD') {
        if (headers['content-length']) {
          headers = filterHeaders(headers, 'content-length')
        }
      } else {
        if (req.body) {
          if (req.body instanceof Stream) {
            body = req.body
          } else if (typeof req.body === 'string') {
            body = req.body
            populateHeaders(headers, body, 'text/plain')
          } else if (headers['content-type'] === 'application/x-www-form-urlencoded') {
            body = new URLSearchParams(req.body).toString()
            populateHeaders(headers, body, 'application/x-www-form-urlencoded')
          } else {
            body = JSON.stringify(req.body)
            populateHeaders(headers, body, 'application/json')
          }
        } else {
          body = req
        }
      }

      const reqParams = {
        method: req.method,
        url,
        qs,
        headers: rewriteRequestHeaders(req, headers),
        body,
        request: reqOpts
      }
      request(reqParams, (err, response) => {
        if (!res.socket || res.socket.destroyed || res.writableEnded) {
          return onClientConnectionTerminated(res, err, response)
        }

        if (err) {
          if (err.code === 'ECONNREFUSED') {
            res.statusCode = 503
            res.end('Service Unavailable')
          } else if (
            err.code === 'ECONNRESET' ||
            err.code === 'UND_ERR_HEADERS_TIMEOUT' ||
            err.code === 'UND_ERR_BODY_TIMEOUT') {
            res.statusCode = 504
            res.end(err.message)
          } else {
            res.statusCode = 500
            res.end(err.message)
          }

          return
        }

        // destructing response from remote
        const { headers, statusCode, stream } = response

        if (sourceHttp2) {
          copyHeaders(
            rewriteHeaders(stripHttp1ConnectionHeaders(headers)),
            res
          )
        } else {
          copyHeaders(rewriteHeaders(headers), res)
        }

        // set origin response code
        res.statusCode = statusCode

        if (onResponse) {
          onResponse(req, res, stream)
        } else {
          pump(stream, res)
        }
      })
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
    return reqUrl.slice(queryIndex)
  }

  return ''
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

function getReqUrl (source, cache, base, opts) {
  const reqBase = opts.base || base
  let url

  if (cache) {
    const cacheKey = reqBase + source
    url = cache.get(cacheKey)
    if (!url) {
      url = buildURL(source, reqBase)
      cache.set(cacheKey, url)
    }
  } else {
    url = buildURL(source, reqBase)
  }

  return url
}

module.exports = fastProxy
module.exports.default = fastProxy
module.exports.fastProxy = fastProxy
