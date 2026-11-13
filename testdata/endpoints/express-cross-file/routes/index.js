// Route registry: every module router is mounted here.
const express = require('express');
const { createAccountRouter } = require('./accounts.route');
const { createAdminRouter } = require('./admin.route');
const reports = require('./reports.route');
const { requireLogin } = require('../middleware/auth');

const router = express.Router();

router.get('/health', health);

router.use('/accounts', createAccountRouter({
  store,
  audit: { enabled: true },
}));
router.use('/admin', requireLogin, createAdminRouter({ store }));
router.use('/legacy', require('./legacy.route'));

// The same router under two prefixes, one of them behind a login.
router.use('/reports', reports.reportRouter);
router.use('/my/reports', requireLogin, reports.reportRouter);

module.exports = router;
