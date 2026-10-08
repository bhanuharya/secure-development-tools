const express = require("express");
const mysql = require("mysql");
const app = express();
const db = mysql.createConnection({ host: "db" });

app.get("/user", (req, res) => {
  db.query("SELECT * FROM users WHERE id = " + req.query.id, (err, rows) => res.json(rows));
});
