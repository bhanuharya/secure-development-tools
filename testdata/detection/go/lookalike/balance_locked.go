package main

import "sync"

func withdrawSafe(mu *sync.Mutex, w *Wallet, amount int64) error {
	mu.Lock()
	defer mu.Unlock()
	if w.Balance < amount {
		return ErrFunds
	}
	w.Balance -= amount
	return db.Save(w).Error
}
