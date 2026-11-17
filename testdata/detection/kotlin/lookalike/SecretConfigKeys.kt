// Configuration keys, message keys and URL paths in secret-named constants.
class SecretConfigKeys {
    companion object {
        private const val KEY_ORDERS_API_KEY = "orders.apikey"
        private const val KEY_JWT_PRIVATE_KEY = "auth.jwt.private_key_path"
        private const val MSG_SUCCESS_TOKEN = "success.token_issued"
        private const val VERIFY_PASSWORD = "/services/orders/api/authenticate"
    }
}
