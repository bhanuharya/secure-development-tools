import { Router } from 'express';

interface PaymentDeps {
  provider: string;
}

export default function paymentsRoutes(deps: PaymentDeps): Router {
  const router = Router();
  const config = { retries: 3 };
  router.post('/', createPayment);
  router.post('/refund', refundPayment);
  return router;
}
