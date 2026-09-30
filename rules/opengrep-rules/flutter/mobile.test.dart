// Fixtures for rules/flutter/mobile.yaml: `ruleid:` marks a line that must match,
// `ok:` a line that must not. Run: opengrep scan --test --config mobile.yaml mobile.test.dart

import 'dart:developer' as developer;

void network() {
  // ruleid: scp.flutter.network.cleartext-http
  final api = Uri.parse("http://api.example.com/v1/orders");
  // ok: scp.flutter.network.cleartext-http
  final secure = Uri.parse("https://api.example.com/v1/orders");
  // ok: scp.flutter.network.cleartext-http
  final emulator = Uri.parse("http://10.0.2.2:8080/debug");
  // ok: scp.flutter.network.cleartext-http
  const svgNamespace = "http://www.w3.org/2000/svg";
}

Future<void> storage(SharedPreferences prefs, String token, FlutterSecureStorage secure) async {
  // ruleid: scp.flutter.storage.shared-preferences-secret
  await prefs.setString("access_token", token);
  // ruleid: scp.flutter.storage.shared-preferences-secret
  await prefs.setString("userPin", token);
  // ok: scp.flutter.storage.shared-preferences-secret
  await prefs.setString("theme", "dark");
  // ok: scp.flutter.storage.shared-preferences-secret
  await secure.write(key: "access_token", value: token);
}

Map<String, String> headers(String userToken) {
  // ruleid: scp.flutter.secrets.hardcoded-api-key
  final fixed = {"Content-Type": "application/json", "x-api-key": "not-a-real-key-example"};
  // ok: scp.flutter.secrets.hardcoded-api-key
  final dynamic = {"Content-Type": "application/json", "x-api-key": userToken};
  final h = <String, String>{};
  // ruleid: scp.flutter.secrets.hardcoded-api-key
  h["Authorization"] = "Basic dXNlcjpwYXNzd29yZA==";
  // ok: scp.flutter.secrets.hardcoded-api-key
  h["Authorization"] = "Bearer $userToken";
  return fixed;
}

void logging(String token, String name) {
  // ruleid: scp.flutter.logging.sensitive-data
  print("login ok, token=$token");
  // ruleid: scp.flutter.logging.sensitive-data
  debugPrint(token);
  // ruleid: scp.flutter.logging.sensitive-data
  developer.log("password reset for $name: $token");
  // ok: scp.flutter.logging.sensitive-data
  print("welcome $name");
}

void webview(WebViewController controller) {
  // ruleid: scp.flutter.webview.javascript-channel
  controller.addJavaScriptChannel("Bridge", onMessageReceived: (message) => handle(message.message));
  // ok: scp.flutter.webview.javascript-channel
  controller.loadRequest(Uri.parse("https://example.com"));
}

void crypto(Key key, String plain) {
  // ruleid: scp.flutter.crypto.static-iv
  final zero = IV.fromLength(16);
  // ruleid: scp.flutter.crypto.static-iv
  final fixed = IV.fromUtf8("1234567890123456");
  // ok: scp.flutter.crypto.static-iv
  final random = IV.fromSecureRandom(16);
}

Future<bool> auth(LocalAuthentication localAuth) async {
  // ruleid: scp.flutter.auth.biometric-allows-fallback
  final a = await localAuth.authenticate(localizedReason: "Pay", options: const AuthenticationOptions(stickyAuth: true, biometricOnly: false));
  // ok: scp.flutter.auth.biometric-allows-fallback
  final b = await localAuth.authenticate(localizedReason: "Pay", options: const AuthenticationOptions(biometricOnly: true));
  return a && b;
}

void deeplinks(AppLinks appLinks) {
  // ruleid: scp.flutter.deeplink.unvalidated-handler
  appLinks.uriLinkStream.listen((uri) => open(uri));
  // ok: scp.flutter.deeplink.unvalidated-handler
  appLinks.toString();
}
