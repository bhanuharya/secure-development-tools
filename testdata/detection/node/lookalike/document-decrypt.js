// A document is decrypted, and the password is compared as a hash.
function read(doc, key) {
  return decrypt(doc.content, key);
}
function check(user, password) {
  return bcrypt.compare(password, user.password);
}
