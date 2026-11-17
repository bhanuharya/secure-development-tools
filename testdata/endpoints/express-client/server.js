const express = require('express');
const http = require('http');
const { verifyJwt, requireRole } = require('./middleware');

const app = express();
const accountsRouter = express.Router();
const base = '/accounts';

app.use(express.json());
app.use('/api', verifyJwt, accountsRouter);

accountsRouter.post('/accounts', createAccount);
accountsRouter.get(`${base}/:id`, getAccount);
accountsRouter.get(`/accounts/${accountId}/notes`, listNotes);
accountsRouter.delete('/accounts/:id', requireRole('admin'), closeAccount);

app.get('/health', health);
// An HTTP client call in a server file: the receiver is not a router.
http.get('/health', checkHealth);

module.exports = { app };
