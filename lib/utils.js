'use strict'

function populateHeaders (headers, body, contentType) {
  headers['content-length'] = Buffer.byteLength(body)

  // only populate content-type if not present
  if (!headers['content-type']) {
    headers['content-type'] = contentType
  }
}

function filterPseudoHeaders (headers) {
  const dest = {}
  const headersKeys = Object.keys(headers)

  // An intermediary that converts an HTTP/2 request to HTTP/1.1
  // MUST create a Host header field if one is not present in a request
  // by copying the value of the :authority pseudo-header field.
  // see: https://httpwg.org/specs/rfc7540.html
  if (!headers.host && headers[':authority']) {
    dest.host = headers[':authority']
  }

  let header
  let i
  for (i = 0; i < headersKeys.length; i++) {
    header = headersKeys[i]
    if (header.charCodeAt(0) !== 58) { // fast path for indexOf(':') === 0
      dest[header.toLowerCase()] = headers[header]
    }
  }

  return dest
}

function copyHeaders (headers, res) {
  const headersKeys = Object.keys(headers)

  let header
  let i
  for (i = 0; i < headersKeys.length; i++) {
    header = headersKeys[i]
    if (header.charCodeAt(0) !== 58) { // fast path for indexOf(':') === 0
      res.setHeader(header, headers[header])
    }
  }
}

function stripHttp1ConnectionHeaders (headers) {
  const headersKeys = Object.keys(headers)
  const dest = {}

  let header
  let i
  for (i = 0; i < headersKeys.length; i++) {
    header = headersKeys[i].toLowerCase()

    switch (header) {
      case 'connection':
      case 'upgrade':
      case 'http2-settings':
      case 'te':
      case 'transfer-encoding':
      case 'proxy-connection':
      case 'keep-alive':
      case 'host':
        break
      default:
        dest[header] = headers[header]
        break
    }
  }
  return dest
}

function filterHeaders (headers, filter) {
  const headersKeys = Object.keys(headers)
  const dest = {}

  let header
  let i
  for (i = 0; i < headersKeys.length; i++) {
    header = headersKeys[i].toLowerCase()
    if (header !== filter) {
      dest[header] = headers[header]
    }
  }
  return dest
}

function buildURL (source = '', reqBase) {
  // issue ref: https://github.com/fastify/fast-proxy/issues/42, https://github.com/fastify/fast-proxy/issues/76
  let i = 0
  while (source[i] === '/') {
    i++
  }
  const cleanSource = i > 0 ? '/' + source.substring(i) : source

  const url = new URL(cleanSource, reqBase)

  // SSRF prevention: validate that the resolved URL stays within the
  // configured base origin. Absolute-form HTTP requests (RFC 7230 §5.3.2)
  // set req.url to the full URL, which bypasses base via the URL constructor.
  if (reqBase) {
    const baseUrl = new URL(reqBase)
    if (url.origin !== baseUrl.origin) {
      throw new Error('SSRF prevention: source "' + source + '" resolves to origin "' + url.origin + '" but base origin is "' + baseUrl.origin + '"')
    }
  }

  return url
}

module.exports = {
  copyHeaders,
  stripHttp1ConnectionHeaders,
  filterPseudoHeaders,
  filterHeaders,
  buildURL,
  populateHeaders
}
