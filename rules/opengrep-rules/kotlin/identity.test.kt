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
