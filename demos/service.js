'use strict'

const bodyParser = require('body-parser')

const service = require('restana')()
service.use(bodyParser.json())

service.get('/service/get', (req, res) => res.send('Hello World!'))

service.post('/service/post', (req, res) => res.send(req.body))

service.get('/service/long', (req, res) => {
  setTimeout(() => res.end(), 10000)
})

service.start(3000)
