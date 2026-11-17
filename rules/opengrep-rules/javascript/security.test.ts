// Annotated TypeScript tests for javascript/security.yaml (rules that declare typescript).
import type { Core } from '@strapi/strapi';
export default ({ env }: Core.Config.Shared.ConfigParams) => ({
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
  constructor(private configService: ConfigService) {}
  secret() {
    // ruleid: scp.javascript.secrets.env-fallback-literal
    return this.configService.get<string>('JWT_SECRET', 'changeme');
  }
  other(cache: Map<string, string>) {
    // ok: scp.javascript.secrets.env-fallback-literal
    return cache.get('JWT_SECRET', 'x');
  }
}
