const express = require('express');

const reportRouter = express.Router();
reportRouter.get('/', listReports);

module.exports = { reportRouter };
