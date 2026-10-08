const express = require("express");
const app = express();
app.use(express.json());

app.post("/calc", (req, res) => {
  res.json({ result: eval(req.body.expression) });
});
