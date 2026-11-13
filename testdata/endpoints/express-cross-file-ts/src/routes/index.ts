import { Router } from 'express';
import { ordersRoutes } from './orders.routes';
import paymentsRoutes from './payments.routes';
import * as admin from './admin.routes';
import { authenticate } from '../middleware/auth';

const router = Router();

router.use('/orders', ordersRoutes());
router.use('/payments', authenticate, paymentsRoutes({ provider: 'card' }));
router.use('/admin', admin.adminRouter);

export default router;
