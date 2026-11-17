const express = require('express');
const { requireLogin, requireRole } = require('../middleware/auth');

function createAccountRouter({ store } = {}) {
  const router = express.Router();
  router.use(requireLogin({ store, options: { strict: true } }));
  router.get('/me', getMe);
  router.post('/transfer', requireRole('teller'), transfer);
  return router;
}

module.exports = { createAccountRouter };
