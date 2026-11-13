const express = require('express');
const requestId = require('./middleware/request-id');
const routes = require('./routes');

const app = express();
app.use(requestId);
app.use((req, res, next) => {
  res.setHeader('X-Frame-Options', 'DENY');
  next();
});
app.use('/api/v1', routes);

module.exports = app;
