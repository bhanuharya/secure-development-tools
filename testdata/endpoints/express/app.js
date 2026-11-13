const express = require('express');
const { verifyJwt, requireRole, auditLog } = require('./middleware');

const app = express();
const catalogRouter = express.Router();
const ordersRouter = express.Router();
const adminRouter = express.Router();
const webhooksRouter = express.Router();

app.use(express.json());

app.get('/health', health);

// The catalog router is mounted without a gate: its routes stay public.
app.use('/api/catalog', catalogRouter);
catalogRouter.get('/items', listItems);
catalogRouter.get('/items/:id', getItem);

// Orders get authentication at the mount point, not in the router.
app.use('/api/orders', verifyJwt, ordersRouter);
ordersRouter.get('/', listOrders);
ordersRouter.post('/', auditLog, createOrder);
ordersRouter.delete('/:id', requireRole('admin'), deleteOrder);

// verifyJwt arrives halfway: it only protects routes registered after it.
app.use('/api/admin', adminRouter);
adminRouter.get('/legacy', legacyReport);
adminRouter.use(verifyJwt);
adminRouter.get('/reports', listReports);
adminRouter.patch('/reports/:id', updateReport);

// Exported and mounted by another file, so its protection is unknown here.
webhooksRouter.post('/events', receiveEvent);

module.exports = { app, webhooksRouter };
