const express = require('express');

const app = express();

// Each factory declares its own `router`; the gate in the first one cannot
// protect a route registered on the second one.
function privateApi() {
  const router = express.Router();
  router.use(requireAuth);
  router.post('/orders', handle);
  app.use('/api/private', router);
}

function publicApi() {
  const router = express.Router();
  router.post('/transfer', handle);
  app.use('/api/public', router);
}
