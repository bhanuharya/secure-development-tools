const express = require('express');

const app = express();
const router = express.Router();

app.use(verifyToken, router);
router.post('/transfer', handleTransfer);
