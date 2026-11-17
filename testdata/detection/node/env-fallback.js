// A CMS config: when the variables are not set, the service signs admin sessions with
// the literal below, which anyone who can read the code or the deployed files knows.
module.exports = ({ env }) => ({
  apiToken: {
    salt: env('API_TOKEN_SALT', 'tobemodified-token-salt'),
  },
  auth: {
    secret: env('ADMIN_JWT_SECRET', 'tobemodified-jwt-secret'),
  },
});
