const express = require('express');

// Not mounted anywhere this scan can see.
const router = express.Router();
router.post('/events', receiveEvent);

module.exports = router;
