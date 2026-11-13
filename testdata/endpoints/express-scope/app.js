const express = require('express');

// Two application factories each declare their own `app`; the gate in the
// first one cannot protect a route of the second.
function privateApp() {
  const app = express();
  app.use(requireAuth);
  app.post('/private', handle);
  return app;
}

function publicApp() {
  const app = express();
  app.post('/transfer', handle);
  return app;
}

const exposed = publicApp();
