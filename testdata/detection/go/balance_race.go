package main

type Wallet struct {
	Balance int64
}

func withdraw(w *Wallet, amount int64) error {
	if w.Balance < amount {
		return ErrFunds
	}
	w.Balance -= amount
	return db.Save(w).Error
}
