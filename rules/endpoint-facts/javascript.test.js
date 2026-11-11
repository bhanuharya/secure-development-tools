// Annotated tests for the Express facts in rules/endpoint-facts/javascript.yaml.
const express = require('express');

// ruleid: fact.js.engine
const app = express();

// ruleid: fact.js.router
const api = express.Router();

// ruleid: fact.js.router
const open = express.Router();

// ruleid: fact.js.use1
app.use(express.json());

// ruleid: fact.js.use1
api.use(verifyJwt);

// ruleid: fact.js.use2
api.use(verifyJwt, auditLog);

// ruleid: fact.js.use3
api.use(verifyJwt, auditLog, rateLimit);

// ruleid: fact.js.use4
api.use(verifyJwt, auditLog, rateLimit, tracer);

// ruleid: fact.js.route1
api.get('/orders', listOrders);

// ruleid: fact.js.route2
api.post('/orders', requireAuth, createOrder);

// ruleid: fact.js.route3
api.put('/orders/:id', requireAuth, rateLimit, updateOrder);

// ruleid: fact.js.route4
api.patch('/orders/:id', requireAuth, rateLimit, tracer, patchOrder);

// ruleid: fact.js.route1
api.delete('/orders/:id', deleteOrder);

// ruleid: fact.js.route1
api.all('/orders/:id', anyOrder);

// ruleid: fact.js.use2
app.use('/api', open);

// ruleid: fact.js.use3
app.use('/api', verifyJwt, open);
