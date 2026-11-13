const express = require('express');
const { verifyToken } = require('./auth');
const registerOrders = require('./routes/orders');
const admin = require('./routes/admin');

const app = express();
const api = express.Router();
api.use(verifyToken);
app.use('/api', api);

require('./routes/health')(app);
registerOrders(api);
admin.register(app);
legacy(app);

function legacy(server) {
  server.post('/legacy/admin/export', exportAll);
}

module.exports = app;
