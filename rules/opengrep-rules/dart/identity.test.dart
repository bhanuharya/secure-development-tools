// Annotated tests for dart/identity.yaml.
class ApiConfig {
  // ruleid: scp.dart.secrets.hardcoded-secret
  static const String clientSecret = 'f3a91c0d7b2e4a6c9d81';
  // ruleid: scp.dart.secrets.hardcoded-secret
  static const aesKey = "0123456789abcdef0123456789abcdef";
  // ok: scp.dart.secrets.hardcoded-secret
  static const String clientSecretHeader = 'x-client-secret';
  // ok: scp.dart.secrets.hardcoded-secret
  static String clientSecretField = 'client_secret';
  // ok: scp.dart.secrets.hardcoded-secret
  static const String passwordHint = 'At least eight characters';
  // ok: scp.dart.secrets.hardcoded-secret
  final String password = '';
}

bool checkPin(Account account, String pin, Encrypter encrypter) {
  // ruleid: scp.dart.crypto.recoverable-password
  return encrypter.decrypt64(account.pin) == pin;
}

String savedLogin(Encrypter encrypter, String storedPassword) {
  // ruleid: scp.dart.crypto.recoverable-password
  return encrypter.decrypt(Encrypted.fromBase64(storedPassword));
}

String readDocument(Encrypter encrypter, Document doc) {
  // ok: scp.dart.crypto.recoverable-password
  return encrypter.decrypt64(doc.content);
}
