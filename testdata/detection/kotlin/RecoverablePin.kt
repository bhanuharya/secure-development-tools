// The stored PIN is decrypted back to clear text.
fun checkPin(account: Account, pin: String): Boolean {
    return Crypto.decrypt(account.pin) == pin
}
