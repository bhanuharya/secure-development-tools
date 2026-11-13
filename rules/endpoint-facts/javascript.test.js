// Annotated tests for the Express facts in rules/endpoint-facts/javascript.yaml.
// ruleid: fact.js.express_import
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

// ruleid: fact.js.route
api.get('/orders', listOrders);

// ruleid: fact.js.route
api.post('/orders', requireAuth, createOrder);

// ruleid: fact.js.route
api.put('/orders/:id', requireAuth, rateLimit, updateOrder);

// ruleid: fact.js.route
api.patch('/orders/:id', requireAuth, rateLimit, tracer, patchOrder);

// ruleid: fact.js.route
api.patch('/orders/:id', requireAuth, rateLimit, tracer, auditLog, patchOrder);

// ruleid: fact.js.route
api.delete('/orders/:id', deleteOrder);

// ruleid: fact.js.route
api.all('/orders/:id', anyOrder);

// ruleid: fact.js.use2
app.use('/api', open);

// ruleid: fact.js.use3
app.use('/api', verifyJwt, open);

// ruleid: fact.js.express_import, fact.js.router
const legacy = require('express').Router();

// ruleid: fact.js.express_import
const { Router } = require('express');

// ruleid: fact.js.router, fact.js.router_fn
const accounts = Router();

// ruleid: fact.js.frontend_import
const React = require('react');

// ruleid: fact.js.frontend_import
import Vue from 'vue';

// ruleid: fact.js.frontend_import
import { Component } from '@angular/core';
