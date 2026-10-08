// Annotated tests for javascript/security.yaml.
function tainted(userInput, el) {
  // ruleid: scp.javascript.injection.eval
  eval(userInput);
  // ruleid: scp.javascript.xss.innerHTML
  el.innerHTML = userInput;
}

function safe(userInput, el) {
  // ok: scp.javascript.injection.eval
  JSON.parse(userInput);
  // ok: scp.javascript.xss.innerHTML
  el.textContent = userInput;
}

const axios = require("axios");

async function proxy(req, res) {
  // ruleid: scp.javascript.ssrf.request-controlled-url
  const response = await axios.get(req.query.url);
  res.send(response.data);
}

const preview = async (req, res) => {
  const target = "https://" + req.body.host + "/status";
  // ruleid: scp.javascript.ssrf.request-controlled-url
  const response = await fetch(target);
  res.send(await response.text());
};

async function fixedPartner(req, res) {
  // ok: scp.javascript.ssrf.request-controlled-url
  const response = await axios.get("https://partner.example.com/items", { params: { id: req.query.id } });
  res.send(response.data);
}
