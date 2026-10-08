const jwt = require("jsonwebtoken");

function sign(user) {
  return jwt.sign({ id: user.id }, "super-secret-jwt-key");
}

function read(token) {
  return jwt.decode(token);
}

function verifyLoose(token, key) {
  return jwt.verify(token, key, { algorithms: ["none", "HS256"] });
}
module.exports = { sign, read, verifyLoose };
