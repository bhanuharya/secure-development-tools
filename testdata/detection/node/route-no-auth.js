const api = require('express').Router();

// The transfer route has no auth middleware while its neighbour has one.
api.post('/orders', verifyJwt, orders.create);
api.post('/funds/transfer', funds.transfer);
