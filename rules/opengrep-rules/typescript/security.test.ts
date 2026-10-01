// Annotated tests for typescript/security.yaml.
function tainted(userInput: string) {
  // ruleid: scp.typescript.injection.eval
  eval(userInput);
}

function safe(userInput: string) {
  // ok: scp.typescript.injection.eval
  JSON.parse(userInput);
}
