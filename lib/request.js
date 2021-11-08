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

  function handleHttp1Req (requests, agents) {
    return (opts, done) => {
      const req = requests[opts.url.protocol].request({
        ...opts.request,
        method: opts.method,
        port: opts.url.port,
        path: opts.url.pathname + opts.qs,
        hostname: opts.url.hostname,
        headers: opts.headers,
        agent: agents[opts.url.protocol]
      })
      req.on('error', done)
      req.on('timeout', () => req.abort())
      req.on('response', res => {
        setImmediate(() => done(null, { statusCode: res.statusCode, headers: res.headers, stream: res }))
      })
      end(req, opts.body, done)
    }
  }

  function agentOption (opts) {
    return {
      keepAlive: true,
      keepAliveMsecs: 60 * 1000, // 1 minute
      maxSockets: 2048,
      maxFreeSockets: 2048,
      ...opts
    }
  }

  function end (req, body, cb) {
    if (!body || typeof body === 'string') {
      req.end(body)
    } else {
      pump(body, req, err => {
        if (err) cb(err)
      })
    }
  }
}

module.exports = buildRequest
