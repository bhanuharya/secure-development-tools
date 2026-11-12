const express = require('express');
const app = express();

// Four loggers precede the handler; none of them is an authentication gate.
app.post('/orders/transfer', logger1, logger2, logger3, logger4, handle);

function logger1(req, res, next) { next(); }
function logger2(req, res, next) { next(); }
function logger3(req, res, next) { next(); }
function logger4(req, res, next) { next(); }
function handle(req, res) { res.sendStatus(204); }
