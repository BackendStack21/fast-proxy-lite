/* global describe, it */
'use strict'

const http = require('http')
const { expect } = require('chai')
let gateway, service, close, proxy
let clientTerminated = false

describe('Client connection terminated', () => {
  it('init', async () => {
    const fastProxy = require('../index')({
      base: 'http://127.0.0.1:3000'
    })

    proxy = fastProxy.proxy
    close = fastProxy.close
  })

  it('init & start gateway', async () => {
    // init gateway
    gateway = require('restana')()

    gateway.all('/service/*', function (req, res) {
      proxy(req, res, req.url, {
        onClientConnectionTerminated (res, _err, response) {
          clientTerminated = true
        }
      })
    })

    await gateway.start(8080)
  })

  it('init & start remote service', async () => {
    // init remote service
    service = require('restana')()

    service.get('/service/long', (req, res) => {
      setTimeout(() => res.end(), 500)
    })

    await service.start(3000)
  })

  it('should invoke onClientConnectionTerminated callback', async () => {
    const options = {
      host: 'localhost',
      path: '/service/long',
      port: 8080,
      method: 'GET',
      headers: {
        'Content-Length': 0
      }
    }
    const req = http.request(options)
    req.on('error', () => {})
    req.end()

    await sleep(100)
    req.destroy()

    await sleep(1000)
    expect(clientTerminated).to.equal(true)
  })

  it('close all', async () => {
    close()
    await gateway.close()
    await service.close()
  })
})

function sleep (ms) {
  return new Promise(resolve => setTimeout(resolve, ms))
}
