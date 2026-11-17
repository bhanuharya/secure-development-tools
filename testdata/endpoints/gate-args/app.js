const express = require('express');
const cors = require('cors');

const app = express();
app.use(cors({ allowedHeaders: ['Authorization'] }));
app.post('/payouts', transferFunds);

function transferFunds(req, res) {}
