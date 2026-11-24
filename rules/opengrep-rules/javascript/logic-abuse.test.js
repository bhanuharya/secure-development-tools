const crypto = require('crypto');

// ---- mass-assignment-req-body

async function updateUnsafe(req, res, prisma, user) {
  // ruleid: scp.javascript.logic.mass-assignment-req-body
  Object.assign(user, req.body);
  // ruleid: scp.javascript.logic.mass-assignment-req-body
  await prisma.user.create({ data: req.body });
}

async function updateSafe(req, res, prisma) {
  const { displayName, bio } = req.body;
  // ok: scp.javascript.logic.mass-assignment-req-body
  await prisma.user.create({ data: { displayName, bio } });
}

// ---- weak-prng-otp-or-token

function makeOtpUnsafe() {
  // ruleid: scp.javascript.logic.weak-prng-otp-or-token
  const otpCode = Math.floor(100000 + Math.random() * 900000);
  // ruleid: scp.javascript.logic.weak-prng-otp-or-token
  const resetToken = Math.random().toString(36).slice(2);
  return { otpCode, resetToken };
}

function makeOtpSafe() {
  // ok: scp.javascript.logic.weak-prng-otp-or-token
  const otpCode = crypto.randomInt(100000, 999999);
  // ok: scp.javascript.logic.weak-prng-otp-or-token
  const retryJitter = Math.floor(Math.random() * 250);
  return { otpCode, retryJitter };
}

// ---- non-constant-time-token-compare

function verifyWebhookUnsafe(expectedSignature, provided) {
  // ruleid: scp.javascript.logic.non-constant-time-token-compare
  return expectedSignature === provided;
}

function verifyWebhookSafe(expectedSignature, provided) {
  // ok: scp.javascript.logic.non-constant-time-token-compare
  if (expectedSignature === '') return false;
  // ok: scp.javascript.logic.non-constant-time-token-compare
  return crypto.timingSafeEqual(Buffer.from(expectedSignature), Buffer.from(provided));
}

// ---- trust-spoofable-identity-header

function headersCheck(req) {
  // ruleid: scp.javascript.logic.trust-spoofable-identity-header
  const uid = req.headers['x-user-id'];
  // ruleid: scp.javascript.logic.trust-spoofable-identity-header
  const role = req.get('X-Role');
  // ok: scp.javascript.logic.trust-spoofable-identity-header
  const trace = req.get('X-Request-Id');
  return { uid, role, trace };
}

// ---- unbounded-pagination-limit

async function listUnsafe(req, prisma) {
  const limit = Number(req.query.limit);
  // ruleid: scp.javascript.logic.unbounded-pagination-limit
  return prisma.order.findMany({ take: limit });
}

async function listSafe(req, prisma) {
  const limit = Math.min(Number(req.query.limit) || 20, 100);
  // ok: scp.javascript.logic.unbounded-pagination-limit
  return prisma.order.findMany({ take: limit });
}
