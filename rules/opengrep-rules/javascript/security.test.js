// Annotated tests for javascript/security.yaml.
function tainted(userInput, el) {
  // ruleid: scp.javascript.injection.eval
  eval(userInput);
  // ruleid: scp.javascript.xss.innerHTML
  el.innerHTML = userInput;
}

function safe(userInput, el) {
  // ok: scp.javascript.injection.eval
  JSON.parse(userInput);
  // ok: scp.javascript.xss.innerHTML
  el.textContent = userInput;
}

const axios = require("axios");

async function proxy(req, res) {
  // ruleid: scp.javascript.ssrf.request-controlled-url
  const response = await axios.get(req.query.url);
  res.send(response.data);
}

const preview = async (req, res) => {
  const target = "https://" + req.body.host + "/status";
  // ruleid: scp.javascript.ssrf.request-controlled-url
  const response = await fetch(target);
  res.send(await response.text());
};

async function fixedPartner(req, res) {
  // ok: scp.javascript.ssrf.request-controlled-url
  const response = await axios.get("https://partner.example.com/items", { params: { id: req.query.id } });
  res.send(response.data);
}

// Secrets read from the environment with a literal fallback.
export default ({ env }) => ({
  // ruleid: scp.javascript.secrets.env-fallback-literal
  apiToken: { salt: env('API_TOKEN_SALT', 'not-a-real-salt') },
  // ruleid: scp.javascript.secrets.env-fallback-literal
  auth: { secret: env('ADMIN_JWT_SECRET', "tobemodified") },
  // ruleid: scp.javascript.secrets.env-fallback-literal
  app: { keys: env.array('APP_KEYS', ['keyOne', 'keyTwo']) },
  // ruleid: scp.javascript.secrets.env-fallback-literal
  connection: { password: env('DATABASE_PASSWORD', 'strapi') },
  // ok: scp.javascript.secrets.env-fallback-literal
  okSecret: env('ADMIN_JWT_SECRET'),
  // ok: scp.javascript.secrets.env-fallback-literal
  okEmpty: env('ADMIN_JWT_SECRET', ''),
  // ok: scp.javascript.secrets.env-fallback-literal
  okHost: env('DATABASE_HOST', '127.0.0.1'),
  // ok: scp.javascript.secrets.env-fallback-literal
  okTtl: env('JWT_TOKEN_EXPIRES_IN', '7d'),
  // ok: scp.javascript.secrets.env-fallback-literal
  okRef: env('PREVIEW_TOKEN', otherToken),
  // ok: scp.javascript.secrets.env-fallback-literal
  okPort: env.int('PORT', 1337),
  // ok: scp.javascript.secrets.env-fallback-literal
  okBypass: env('BYPASS_CACHE', 'true'),
});
// ruleid: scp.javascript.secrets.env-fallback-literal
const jwtSecret = process.env.JWT_SECRET || 'dev-secret';
// ruleid: scp.javascript.secrets.env-fallback-literal
const dbPass = process.env['DB_PASS'] ?? "postgres";
// Not covered: a default in a destructuring of process.env.
const { SESSION_SECRET = 'keyboard cat' } = process.env;
// ok: scp.javascript.secrets.env-fallback-literal
const pwd = process.env.PWD || '/app';
// ok: scp.javascript.secrets.env-fallback-literal
const header = process.env.API_KEY_HEADER || 'x-api-key';
// ok: scp.javascript.secrets.env-fallback-literal
const strict = process.env.JWT_SECRET;
class AuthModule {
  constructor(configService) { this.configService = configService; }
  secret() {
    // ruleid: scp.javascript.secrets.env-fallback-literal
    return this.configService.get('JWT_SECRET', 'changeme');
  }
  other(cache) {
    // ok: scp.javascript.secrets.env-fallback-literal
    return cache.get('JWT_SECRET', 'x');
  }
}
// literal-basic-credential
// ruleid: scp.javascript.secrets.literal-basic-credential
const auth = 'Basic ' + btoa('notify-client:example-not-a-real-pass');
// ruleid: scp.javascript.secrets.literal-basic-credential
const header = { Authorization: `Basic ${Buffer.from('notify-client:example-pass').toString('base64')}` };
// ok: scp.javascript.secrets.literal-basic-credential
const fromUser = 'Basic ' + btoa(`${username}:${password}`);
// ok: scp.javascript.secrets.literal-basic-credential
const label = btoa('hello world');
