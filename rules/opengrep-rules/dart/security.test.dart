// Annotated tests for dart/security.yaml.
import 'dart:io';
import 'dart:math';

import 'package:crypto/crypto.dart';
import 'package:crypto/crypto.dart' as crypto;
import 'package:encrypt/encrypt.dart';
import "package:encrypt/encrypt.dart" as encryption;
import 'package:sqlite3/sqlite3.dart';
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

void taintedTlsBlock() {
  final client = HttpClient();
  // ruleid: scp.dart.tls.disable-certificate-validation
  client.badCertificateCallback = (X509Certificate cert, String host, int port) { return true; };
}

void safeTlsBlock() {
  final client = HttpClient();
  // ok: scp.dart.tls.disable-certificate-validation
  client.badCertificateCallback = (cert, host, port) { return host == 'localhost'; };
}

void taintedTlsCascade() {
  // ruleid: scp.dart.tls.disable-certificate-validation
  HttpClient()..badCertificateCallback = (cert, host, port) => true;
}

void taintedTlsUntypedBlock() {
  final client = HttpClient();
  // ruleid: scp.dart.tls.disable-certificate-validation
  client.badCertificateCallback = (cert, host, port) { return true; };
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

void taintedStart(String arg) {
  // ruleid: scp.dart.injection.command
  Process.start('bash', ['-c', arg]);
  // ruleid: scp.dart.injection.command
  Process.start('cmd', ['/c', arg]);
}

void taintedCmdRun(String arg) {
  // ruleid: scp.dart.injection.command
  Process.run('cmd', ['/c', arg]);
}

void safeStart(String arg) {
  // ok: scp.dart.injection.command
  Process.start('git', ['status', '--short']);
}

void taintedMd5(List<int> data) {
  // ruleid: scp.dart.crypto.weak-md5
  md5.convert(data);
}

void taintedPrefixedMd5(List<int> data) {
  // ruleid: scp.dart.crypto.weak-md5
  crypto.md5.convert(data);
}

void safeSha256(List<int> data) {
  // ok: scp.dart.crypto.weak-md5
  sha256.convert(data);
}

void taintedSha1(List<int> data) {
  // ruleid: scp.dart.crypto.weak-sha1
  sha1.convert(data);
}

void taintedPrefixedSha1(List<int> data) {
  // ruleid: scp.dart.crypto.weak-sha1
  crypto.sha1.convert(data);
}

void taintedEcb(Key key) {
  // ruleid: scp.dart.crypto.aes-ecb
  final cipher = AES(key, mode: AESMode.ecb);
}

void safeAes(Key key) {
  // ok: scp.dart.crypto.aes-ecb
  final cipher = AES(key, mode: AESMode.sic);
}

void taintedZeroKey() {
  // ruleid: scp.dart.crypto.zero-key
  final cipher = AES(Key.allZerosOfLength(32));
}

void taintedPrefixedAes() {
  // ruleid: scp.dart.crypto.aes-ecb
  final cipher = encryption.AES(encryption.Key.fromLength(32), mode: encryption.AESMode.ecb);
  // ruleid: scp.dart.crypto.zero-key
  final weak = encryption.AES(encryption.Key.allZerosOfLength(32));
}

void safeKey() {
  // ok: scp.dart.crypto.zero-key
  final cipher = AES(Key.fromLength(32));
}

void taintedSql(HttpRequest request, dynamic db) {
  final input = request.uri.queryParameters['id'];
  // ruleid: scp.dart.injection.sql
  db.select('SELECT * FROM users WHERE id = $input');
}

void safeSql(HttpRequest request, dynamic db) {
  final input = request.uri.queryParameters['id'];
  // ok: scp.dart.injection.sql
  db.select('SELECT * FROM users WHERE id = ?', [input]);
}

void taintedSqlExecute(HttpRequest request, dynamic db) {
  final input = request.uri.queryParameters['name'];
  // ruleid: scp.dart.injection.sql
  db.execute('DELETE FROM users WHERE name = ' + input!);
}

void taintedSqlPrepare(HttpRequest request, dynamic db) {
  final input = request.uri.queryParameters['name'];
  // ruleid: scp.dart.injection.sql
  db.prepare('SELECT * FROM users WHERE name = $input');
}

void safeSqlParameterExecute(HttpRequest request, dynamic db) {
  final input = request.uri.queryParameters['name'];
  // ok: scp.dart.injection.sql
  db.execute('DELETE FROM users WHERE name = ?', [input]);
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

void taintedScript(dynamic textController, WebViewController webView) {
  final input = textController.text;
  // ruleid: scp.dart.webview.untrusted-script
  webView.runJavaScript('show("$input")');
}

void safeScript(dynamic textController, WebViewController webView) {
  final input = textController.text;
  // ok: scp.dart.webview.untrusted-script
  webView.runJavaScript('showFixedMessage()');
}

void taintedScriptResult(dynamic message, WebViewController webView) {
  final input = message.message;
  // ruleid: scp.dart.webview.untrusted-script
  webView.runJavaScriptReturningResult('show("$input")');
}
