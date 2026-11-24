'use strict'

const FORM_URLENCODED = 'application/x-www-form-urlencoded'

// Maximum nesting honoured when serializing a parsed body back to
// application/x-www-form-urlencoded. Guards against cyclic structures.
const FORM_MAX_DEPTH = 16

// Matches request paths that the WHATWG URL parser would silently rewrite into
// a different hierarchy than the one the caller (router, ACL middleware...)
// has seen:
//  - "\" is treated as "/" for http(s) URLs
//  - TAB, LF and CR are removed from anywhere in the input
//  - "." and ".." segments (also "%2e" encoded, case-insensitive) are resolved
// Forwarding the rewritten path would allow escaping a route prefix
// (e.g. "/public/../admin" matching a "/public/*" route but reaching "/admin").
const UNSAFE_PATH = /[\\\t\n\r]|(?:^|\/)(?:\.|%2[eE]){1,2}(?:\/|$)/

const DIGITS_ONLY = /^\d+$/

let lastBase = null
let lastBaseOrigin = null

function getBaseOrigin (reqBase) {
  if (reqBase !== lastBase) {
    lastBaseOrigin = new URL(reqBase).origin
    lastBase = reqBase
  }

  return lastBaseOrigin
}

function populateHeaders (headers, body, contentType) {
  headers['content-length'] = Buffer.byteLength(body)

  // only populate content-type if not present
  if (!headers['content-type']) {
    headers['content-type'] = contentType
  }
}

/**
 * Builds the headers to be sent to the remote server from the incoming
 * request headers. A new object is always returned.
 *
 * The following headers are never forwarded:
 *  - HTTP/2 pseudo headers
 *  - hop-by-hop headers (RFC 9110 §7.6.1). Forwarding "upgrade"/"connection"
 *    lets a client switch the upstream connection to a protocol the proxy
 *    does not relay, "connection: close" defeats upstream connection reuse.
 *  - "expect": the expectation was already handled by the incoming server
 *  - message framing headers ("content-length", "transfer-encoding"): framing
 *    of the upstream request is decided by the proxy, never by the client.
 *    Forwarding both, or none for a request with a body, enables HTTP request
 *    smuggling.
 *
 * Headers nominated by the client "Connection" header are intentionally NOT
 * removed: honouring them would allow a client to strip headers that were
 * added by trusted middlewares (auth context, x-forwarded-*...).
 */
function buildRequestHeaders (reqHeaders) {
  const dest = {}
  const keys = Object.keys(reqHeaders)

  let key
  let name
  let i
  for (i = 0; i < keys.length; i++) {
    key = keys[i]
    if (key.charCodeAt(0) === 58) { // fast path for indexOf(':') === 0
      continue
    }

    name = key.toLowerCase()
    switch (name) {
      case 'connection':
      case 'keep-alive':
      case 'proxy-connection':
      case 'proxy-authorization':
      case 'te':
      case 'trailer':
      case 'transfer-encoding':
      case 'upgrade':
      case 'http2-settings':
      case 'expect':
      case 'content-length':
        break
      default:
        dest[name] = reqHeaders[key]
        break
    }
  }

  return dest
}

function copyHeaders (headers, res) {
  const headersKeys = Object.keys(headers)

  let header
  let value
  let i
  for (i = 0; i < headersKeys.length; i++) {
    header = headersKeys[i]
    if (header.charCodeAt(0) !== 58) { // fast path for indexOf(':') === 0
      value = headers[header]
      if (value !== undefined && value !== null) {
        res.setHeader(header, value)
      }
    }
  }
}

/**
 * Removes from the remote response all the headers that are only meaningful
 * for the proxy <-> remote connection (RFC 9110 §7.6.1), including the ones
 * nominated by the remote "Connection" header.
 */
function stripHttp1ConnectionHeaders (headers) {
  const headersKeys = Object.keys(headers)
  const dest = {}

  let connection
  let key
  let header
  let i
  for (i = 0; i < headersKeys.length; i++) {
    key = headersKeys[i]
    header = key.toLowerCase()

    switch (header) {
      case 'connection':
        connection = headers[key]
        break
      case 'upgrade':
      case 'http2-settings':
      case 'te':
      case 'trailer':
      case 'transfer-encoding':
      case 'proxy-connection':
      case 'proxy-authenticate':
      case 'keep-alive':
      case 'host':
        break
      default:
        dest[header] = headers[key]
        break
    }
  }

  if (connection !== undefined && connection !== 'keep-alive' && connection !== 'close') {
    removeConnectionTokens(dest, connection)
  }

  return dest
}

function removeConnectionTokens (dest, connection) {
  const tokens = String(connection).split(',')

  let token
  let i
  for (i = 0; i < tokens.length; i++) {
    token = tokens[i].trim().toLowerCase()
    if (token.length > 0 && token in dest) {
      delete dest[token]
    }
  }
}

function isValidContentLength (value) {
  return typeof value === 'string' && DIGITS_ONLY.test(value)
}

function isFormUrlEncoded (contentType) {
  if (contentType === FORM_URLENCODED) {
    return true
  }
  if (typeof contentType !== 'string') {
    return false
  }

  // media type parameters, e.g: "application/x-www-form-urlencoded; charset=UTF-8"
  const paramsIndex = contentType.indexOf(';')
  const mediaType = paramsIndex === -1 ? contentType : contentType.slice(0, paramsIndex)

  return mediaType.trim().toLowerCase() === FORM_URLENCODED
}

function isEmptyPlainObject (value) {
  const proto = Object.getPrototypeOf(value)
  if (proto !== Object.prototype && proto !== null) {
    return false
  }

  // eslint-disable-next-line no-unreachable-loop
  for (const key in value) { // eslint-disable-line no-unused-vars
    return false
  }

  return true
}

/**
 * Serializes an already parsed body back to application/x-www-form-urlencoded.
 * Arrays are sent as repeated keys ("a=1&a=2") and nested objects using the
 * bracket notation ("a[b]=1"), which is what "qs"/"body-parser" understand.
 */
function toFormUrlEncoded (body) {
  const params = new URLSearchParams()
  const keys = Object.keys(body)

  for (let i = 0; i < keys.length; i++) {
    appendFormValue(params, keys[i], body[keys[i]], 0)
  }

  return params.toString()
}

function appendFormValue (params, key, value, depth) {
  if (value === undefined || value === null) {
    params.append(key, '')
  } else if (typeof value !== 'object' || depth >= FORM_MAX_DEPTH) {
    params.append(key, String(value))
  } else if (Array.isArray(value)) {
    for (let i = 0; i < value.length; i++) {
      if (value[i] !== null && typeof value[i] === 'object') {
        appendFormValue(params, key + '[' + i + ']', value[i], depth + 1)
      } else {
        appendFormValue(params, key, value[i], depth + 1)
      }
    }
  } else {
    const keys = Object.keys(value)
    for (let i = 0; i < keys.length; i++) {
      appendFormValue(params, key + '[' + keys[i] + ']', value[keys[i]], depth + 1)
    }
  }
}

function buildURL (source = '', reqBase) {
  if (typeof source !== 'string') {
    throw new TypeError('The proxy source must be a string')
  }

  // only the path is inspected, query string and fragment are free-form
  let pathEnd = source.indexOf('?')
  const hashIndex = source.indexOf('#')
  if (hashIndex !== -1 && (pathEnd === -1 || hashIndex < pathEnd)) {
    pathEnd = hashIndex
  }
  if (UNSAFE_PATH.test(pathEnd === -1 ? source : source.slice(0, pathEnd))) {
    throw new Error('Unsafe path: dot segments, backslashes and control characters are not allowed')
  }

  // issue ref: https://github.com/fastify/fast-proxy/issues/42, https://github.com/fastify/fast-proxy/issues/76
  let i = 0
  while (source[i] === '/') {
    i++
  }
  const cleanSource = i > 1 ? '/' + source.substring(i) : source

  const url = new URL(cleanSource, reqBase)

  // only protocols the proxy is able to speak are allowed
  if (url.protocol !== 'http:' && url.protocol !== 'https:') {
    throw new Error('Unsupported protocol')
  }

  // SSRF prevention: validate that the resolved URL stays within the
  // configured base origin. Absolute-form HTTP requests (RFC 7230 §5.3.2)
  // set req.url to the full URL, which bypasses base via the URL constructor.
  if (reqBase && url.origin !== getBaseOrigin(reqBase)) {
    throw new Error('SSRF prevention: source resolves to an origin different than the base origin')
  }

  return url
}

module.exports = {
  buildRequestHeaders,
  copyHeaders,
  stripHttp1ConnectionHeaders,
  isValidContentLength,
  isFormUrlEncoded,
  isEmptyPlainObject,
  toFormUrlEncoded,
  buildURL,
  populateHeaders
}
