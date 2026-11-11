# The stored PIN is decrypted back to clear text.
def check_pin(account, pin, fernet):
    return fernet.decrypt(account.pin) == pin
