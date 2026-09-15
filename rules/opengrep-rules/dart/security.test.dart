// Annotated tests for dart/security.yaml.
import 'dart:io';
import 'dart:math';

import 'package:crypto/crypto.dart';
import 'package:webview_flutter/webview_flutter.dart';

void taintedTls() {
  final client = HttpClient();
  // ruleid: scp.dart.tls.disable-certificate-validation
  client.badCertificateCallback = (cert, host, port) => true;
}

void safeTls() {
  final client = HttpClient();
  // ok: scp.dart.tls.disable-certificate-validation
  client.badCertificateCallback = (cert, host, port) => cert != null;
}

void taintedCommand(String arg) {
  // ruleid: scp.dart.injection.command
  Process.run('sh', ['-c', arg]);
}

void taintedCommandSync(String arg) {
  // ruleid: scp.dart.injection.command
  Process.runSync('/bin/sh', ['-c', arg]);
}

void safeProcess(String path) {
  // ok: scp.dart.injection.command
  Process.run('ls', [path]);
}

void taintedMd5(List<int> data) {
  // ruleid: scp.dart.crypto.weak-md5
  md5.convert(data);
}

void safeSha256(List<int> data) {
  // ok: scp.dart.crypto.weak-md5
  sha256.convert(data);
}

void taintedSha1(List<int> data) {
  // ruleid: scp.dart.crypto.weak-sha1
  sha1.convert(data);
}

String taintedRandom() {
  // ruleid: scp.dart.random.insecure
  final r = Random();
  return r.nextInt(1000).toString();
}

String safeRandom() {
  // ok: scp.dart.random.insecure
  final r = Random.secure();
  return r.nextInt(1000).toString();
}

WebViewController taintedWebView() {
  return WebViewController()
    // ruleid: scp.dart.webview.javascript-unrestricted
    ..setJavaScriptMode(JavaScriptMode.unrestricted);
}

WebViewController safeWebView() {
  return WebViewController()
    // ok: scp.dart.webview.javascript-unrestricted
    ..setJavaScriptMode(JavaScriptMode.disabled);
}
