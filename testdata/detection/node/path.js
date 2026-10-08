const express = require("express");
const fs = require("fs");
const path = require("path");
const app = express();

app.get("/download", (req, res) => {
  const file = path.join(__dirname, "reports", req.query.file);
  fs.readFile(file, (err, data) => res.send(data));
});

app.get("/static", (req, res) => {
  res.sendFile("/srv/files/" + req.query.name);
});
