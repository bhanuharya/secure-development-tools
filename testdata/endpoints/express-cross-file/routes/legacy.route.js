const express = require('express');

const router = express.Router();
router.post('/admin/export', exportEverything);

module.exports = router;
