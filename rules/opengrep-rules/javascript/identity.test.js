// Annotated tests for javascript/identity.yaml.
const router = require('express').Router();

// ---- credential-change-by-request-id
// ruleid: scp.javascript.authz.credential-change-by-request-id
router.put('/users/:id/reset-password', authenticate, async (req, res) => {
  await users.updatePassword(req.params.id, req.body.password);
  res.json({ ok: true });
});

// ruleid: scp.javascript.authz.credential-change-by-request-id, scp.javascript.authz.route-without-auth-middleware
router.post('/accounts/:accountId/update-email', function (req, res) {
  users.updateEmail(req.params.accountId, req.body.email);
  res.send('ok');
});

// ok: scp.javascript.authz.credential-change-by-request-id
router.put('/users/:id/change-password', authenticate, async (req, res) => {
  if (req.user.id !== req.params.id) return res.status(403).end();
  await users.changePassword(req.params.id, req.body.oldPassword, req.body.password);
  res.json({ ok: true });
});

// ok: scp.javascript.authz.credential-change-by-request-id
router.put('/admin/users/:id/reset-password', authenticate, requireRole('admin'), async (req, res) => {
  await users.resetPassword(req.params.id);
  res.json({ ok: true });
});

// ok: scp.javascript.authz.credential-change-by-request-id
router.put('/users/:id/preferences', authenticate, async (req, res) => {
  await users.updatePreferences(req.params.id, req.body);
  res.json({ ok: true });
});

// ---- recoverable-password
function checkPin(account, pin) {
  // ruleid: scp.javascript.crypto.recoverable-password
  return decrypt(account.pin) === pin;
}
function checkPassword(user, password, key) {
  // ruleid: scp.javascript.crypto.recoverable-password
  return CryptoJS.AES.decrypt(user.password, key).toString() === password;
}
function readDocument(doc, key) {
  // ok: scp.javascript.crypto.recoverable-password
  return decrypt(doc.content, key);
}
function checkHash(user, password) {
  // ok: scp.javascript.crypto.recoverable-password
  return bcrypt.compare(password, user.password);
}

// ---- secret-in-log
function login(username, password, otp, session) {
  // ruleid: scp.javascript.logging.secret-in-log
  logger.info('login attempt', username, password);
  // ruleid: scp.javascript.logging.secret-in-log
  logger.debug(`otp for ${username} is ${otp}`);
  // ruleid: scp.javascript.logging.secret-in-log
  logger.info({ user: username, token: session.accessToken });
  // ok: scp.javascript.logging.secret-in-log
  logger.info('login attempt', username);
  // ok: scp.javascript.logging.secret-in-log
  logger.debug(`token length ${session.accessToken.length}`);
  // ok: scp.javascript.logging.secret-in-log
  logger.info('next page', session.nextPageToken);
}

// ---- route-without-auth-middleware
const api = require('express').Router();
api.post('/orders', verifyJwt, orders.create);
// ruleid: scp.javascript.authz.route-without-auth-middleware
api.post('/funds/transfer', funds.transfer);
// ok: scp.javascript.authz.route-without-auth-middleware
api.post('/login', auth.login);
// ok: scp.javascript.authz.route-without-auth-middleware
api.get('/quotes', quotes.list);
// ok: scp.javascript.authz.route-without-auth-middleware
api.put('/profile', verifyJwt, profile.update);

// ---- hardcoded-secret
// ruleid: scp.javascript.secrets.hardcoded-secret
const SIGNING_SECRET = 'Ex4mpleSecretValue91';
// ruleid: scp.javascript.secrets.hardcoded-secret
let apiKey = "abcDEF1234567890";
// ruleid: scp.javascript.secrets.hardcoded-secret
const ACCESS_TOKEN = "eyJhbGciOiJIUzI1NiJ9.abc123";
class SecretConfig {
  // ruleid: scp.javascript.secrets.hardcoded-secret
  clientSecret = "f3a91c0d7b2e4a6c9d81";
}
// ok: scp.javascript.secrets.hardcoded-secret
const CLIENT_SECRET = 'client_secret';
// ok: scp.javascript.secrets.hardcoded-secret
const API_KEY = 'X-Api-Key';
// ok: scp.javascript.secrets.hardcoded-secret
const JWT_SECRET = '/oauth/token';
// ok: scp.javascript.secrets.hardcoded-secret
const APP_SECRET = 'jwt.secret';
// ok: scp.javascript.secrets.hardcoded-secret
const PASSWORD = 'changeme';
// ok: scp.javascript.secrets.hardcoded-secret
const ADMIN_PASSWORD = 'password';
// ok: scp.javascript.secrets.hardcoded-secret
const DB_PASSWORD = 'At least eight characters';
// ok: scp.javascript.secrets.hardcoded-secret
const ENCRYPTION_KEY = '';
// ok: scp.javascript.secrets.hardcoded-secret
const SIGNING_SECRET = '${SIGNING_KEY}';
// ok: scp.javascript.secrets.hardcoded-secret
const TOKEN = 'abc123456789';
// ok: scp.javascript.secrets.hardcoded-secret
const PRIVATE_KEY = '-----BEGIN PRIVATE KEY-----';
// ok: scp.javascript.secrets.hardcoded-secret
const API_SECRET = 'https://example.com/oauth/token';

// A JWT-shaped value is still material: the segments hold uppercase letters.
// ruleid: scp.javascript.secrets.hardcoded-secret
const JWT_TOKEN = 'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJvcmRlcnMifQ.c2lnbmF0dXJl';
// ok: scp.javascript.secrets.hardcoded-secret
const KEY_ORDERS_API_KEY = 'orders.apikey';
// ok: scp.javascript.secrets.hardcoded-secret
const KEY_JWT_PRIVATE_KEY = 'auth.jwt.private_key_path';
// ok: scp.javascript.secrets.hardcoded-secret
const MSG_SUCCESS_TOKEN = 'success.token_issued';
// ok: scp.javascript.secrets.hardcoded-secret
const VERIFY_PASSWORD = '/services/orders/api/authenticate';
