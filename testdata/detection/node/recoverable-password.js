// The stored password is decrypted back to clear text.
function check(user, password, key) {
  return CryptoJS.AES.decrypt(user.password, key).toString() === password;
}
