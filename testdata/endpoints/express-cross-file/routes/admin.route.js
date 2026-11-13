const express = require('express');
const { requireRole } = require('../middleware/auth');

function createAdminRouter() {
  const router = express.Router();
  router.get('/users', listUsers);
  router.delete('/users/:id', requireRole('admin'), deleteUser);
  return router;
}

module.exports = { createAdminRouter };
