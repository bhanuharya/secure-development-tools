const https = require("https");
const crypto = require("crypto");

const agent = new https.Agent({ rejectUnauthorized: false });

function resetToken() {
  return Math.random().toString(36).slice(2);
}

function hashPassword(password) {
  return crypto.createHash("md5").update(password).digest("hex");
}
module.exports = { agent, resetToken, hashPassword };
