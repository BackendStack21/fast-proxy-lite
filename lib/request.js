'use strict'

const http = require('http')
const https = require('https')
const pump = require('pump')

function buildRequest (opts) {
  const requests = {
    'http:': opts.requests && opts.requests.http ? opts.requests.http : http,
    'https:': opts.requests && opts.requests.https ? opts.requests.https : https
  }

  const agents = {
    'http:': new http.Agent(agentOption(opts)),
    'https:': new https.Agent(agentOption(opts))
  }

  return {
    request: handleHttp1Req(requests, agents),
    close: () => {
      agents['http:'].destroy()
      agents['https:'].destroy()
    }
  }

  /**
   * Sends the request to the remote server.
   * "done" is guaranteed to be invoked at most once: either with the error
   * that prevented a response from being received, or with the response.
   * Returns a function that aborts the request.
   */
  function handleHttp1Req (requests, agents) {
    return (opts, done) => {
      const url = opts.url
      let settled = false

      const finish = (err, response) => {
        if (settled) {
          return
        }
        settled = true
        done(err, response)
      }
      const onProtocolSwitch = (res, socket) => {
        // the connection can't be reused
        socket.destroy()
        finish(createError('Unexpected protocol switch from remote server', 'ERR_UNEXPECTED_PROTOCOL_SWITCH'))
      }

      const req = requests[url.protocol].request({
        ...opts.request,
        method: opts.method,
        port: url.port,
        path: url.pathname + opts.qs,
        hostname: url.hostname,
        headers: opts.headers,
        agent: agents[url.protocol]
      })
      // this listener must remain attached for the whole request lifecycle,
      // errors raised after a response was received are reported by the
      // response stream itself
      req.on('error', finish)
      req.on('timeout', () => destroy(req, createError('Remote server timeout', 'ETIMEDOUT')))
      // protocol switching and tunnels are not supported, without these
      // listeners the request would never be settled
      req.on('upgrade', onProtocolSwitch)
      req.on('connect', onProtocolSwitch)
      req.on('response', res => {
        if (settled) {
          // nobody is going to consume this response
          res.destroy()

          return
        }
        finish(null, { statusCode: res.statusCode, headers: res.headers, stream: res })
      })
      end(req, opts.body, finish)

      return err => {
        finish(err)
        destroy(req, err)
      }
    }
  }

  function agentOption (opts) {
    // "base", "cacheURLs" and "requests" are not agent/socket options
    const { base, cacheURLs, requests, ...agentOpts } = opts

    return {
      keepAlive: true,
      keepAliveMsecs: 60 * 1000, // 1 minute
      maxSockets: 2048,
      maxFreeSockets: 2048,
      ...agentOpts
    }
  }

  function end (req, body, cb) {
    if (!body || typeof body === 'string' || Buffer.isBuffer(body)) {
      req.end(body)
    } else {
      pump(body, req, err => {
        if (err) cb(err)
      })
    }
  }
}

function createError (message, code) {
  const err = new Error(message)
  err.code = code

  return err
}

function destroy (req, err) {
  if (typeof req.destroy === 'function') {
    req.destroy(err)
  } else {
    req.abort()
  }
}

module.exports = buildRequest
module.exports.createError = createError
