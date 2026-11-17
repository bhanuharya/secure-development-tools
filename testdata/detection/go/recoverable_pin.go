package main

// The stored PIN is decrypted back to clear text.
func checkPin(account Account, pin string) bool {
	clear, _ := crypto.Decrypt(account.Pin, key)
	return clear == pin
}
