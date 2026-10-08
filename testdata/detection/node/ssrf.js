const express = require("express");
const axios = require("axios");
const app = express();

app.get("/proxy", async (req, res) => {
  const response = await axios.get(req.query.url);
  res.send(response.data);
});
