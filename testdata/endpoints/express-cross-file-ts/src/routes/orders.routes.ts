import { Router } from 'express';
import { authenticate, hasRole } from '../middleware/auth';

export const ordersRoutes = (): Router => {
  const router = Router();
  router.use(authenticate);
  router.get('/', listOrders);
  router.delete('/:id', hasRole('manager'), cancelOrder);
  return router;
};
