// Annotated tests for kotlin/identity.yaml.
fun login(username: String, password: String, otp: String, session: Session) {
    // ruleid: scp.kotlin.logging.secret-in-log
    Log.d("Auth", password)
    // ruleid: scp.kotlin.logging.secret-in-log
    Log.d("Auth", "otp for $username is $otp")
    // ruleid: scp.kotlin.logging.secret-in-log
    Timber.i("token ${session.accessToken}")
    // ok: scp.kotlin.logging.secret-in-log
    Log.d("Auth", "login attempt for $username")
    // ok: scp.kotlin.logging.secret-in-log
    Log.d("Auth", "token length ${session.accessToken.length}")
    // ok: scp.kotlin.logging.secret-in-log
    Log.d("Push", "registered $fcmToken")
}

fun checkPin(account: Account, pin: String): Boolean {
    // ruleid: scp.kotlin.crypto.recoverable-password
    return Crypto.decrypt(account.pin) == pin
}

fun readDocument(doc: Document): ByteArray {
    // ok: scp.kotlin.crypto.recoverable-password
    return Crypto.decrypt(doc.content)
}

// ---- hardcoded-secret
object SecretConstants {
    // ruleid: scp.kotlin.secrets.hardcoded-secret
    private const val CLIENT_SECRET = "Ex4mpleSecretValue91"
    // ruleid: scp.kotlin.secrets.hardcoded-secret
    private const val SIGNING_KEY = "s1gning-Key-Value-2024"
    // ruleid: scp.kotlin.secrets.hardcoded-secret
    private val apiKey: String = "abcDEF1234567890"
    // ruleid: scp.kotlin.secrets.hardcoded-secret
    private val authToken = "eyJhbGciOiJIUzI1NiJ9.abc123"
}

object SecretLookalikes {
    // ok: scp.kotlin.secrets.hardcoded-secret
    private const val CLIENT_SECRET = "client_secret"
    // ok: scp.kotlin.secrets.hardcoded-secret
    private const val API_KEY = "X-Api-Key"
    // ok: scp.kotlin.secrets.hardcoded-secret
    private const val JWT_SECRET = "/oauth/token"
    // ok: scp.kotlin.secrets.hardcoded-secret
    private const val APP_SECRET = "jwt.secret"
    // ok: scp.kotlin.secrets.hardcoded-secret
    private const val PASSWORD = "changeme"
    // ok: scp.kotlin.secrets.hardcoded-secret
    private const val ADMIN_PASSWORD = "password"
    // ok: scp.kotlin.secrets.hardcoded-secret
    private const val DB_PASSWORD = "At least eight characters"
    // ok: scp.kotlin.secrets.hardcoded-secret
    private val ACCESS_TOKEN = ""
    // ok: scp.kotlin.secrets.hardcoded-secret
    private val SIGNING_SECRET = "${SIGNING_KEY}"
    // ok: scp.kotlin.secrets.hardcoded-secret
    private const val PRIVATE_KEY = "-----BEGIN PRIVATE KEY-----"
    // ok: scp.kotlin.secrets.hardcoded-secret
    private val passwordHint = "At least eight characters"
}
