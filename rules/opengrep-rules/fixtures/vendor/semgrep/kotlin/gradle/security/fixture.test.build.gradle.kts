// Fixture for build-gradle-password-hardcoded (SDT-authored; upstream ships none).
val env = System.getenv()
// ruleid: build-gradle-password-hardcoded
val password = env["SIGNING_PASSWORD"] ?: "c2VjcmV0UGFzc3dvcmQ"
// ok: build-gradle-password-hardcoded
val username = env["SIGNING_USER"] ?: "builder"
