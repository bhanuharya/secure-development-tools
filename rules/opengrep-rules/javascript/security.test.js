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
