package main

import (
	"database/sql"
	"fmt"
	"net/http"
)

func user(db *sql.DB, w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("name")
	rows, _ := db.Query("SELECT id FROM users WHERE name = '" + name + "'")
	defer rows.Close()
	q := fmt.Sprintf("DELETE FROM users WHERE id = %s", r.URL.Query().Get("id"))
	db.Exec(q)
}
