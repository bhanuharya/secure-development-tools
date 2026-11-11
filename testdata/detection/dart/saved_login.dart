// The saved password is decrypted on the device.
String savedLogin(Encrypter encrypter, String storedPassword) {
  return encrypter.decrypt(Encrypted.fromBase64(storedPassword));
}
