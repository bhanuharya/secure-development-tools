package endpoints

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

// TestJSModuleShapes pins the import and export forms the cross-file mount
// linking reads, CommonJS and ESM alike.
func TestJSModuleShapes(t *testing.T) {
	root := writeTree(t, map[string]string{
		"lib/a.js":       "module.exports = {};\n",
		"lib/b.ts":       "export const b = 1;\n",
		"lib/c/index.js": "module.exports = {};\n",
		"lib/main.js": `const a = require('./a');
const { x, y: yy } = require('./a');
const pick = require('./a').pick;
import b from './b.js';
import d, { e, f as ff } from './b';
import * as ns from './c';
import pkg from 'express';
// const commented = require('./a');
module.exports = { router, make: makeRouter };
exports.extra = other;
`,
	})
	m := readJSModule(root, "lib/main.js")
	want := map[string]jsImport{
		"a":    {file: "lib/a.js", name: "default"},
		"x":    {file: "lib/a.js", name: "x"},
		"yy":   {file: "lib/a.js", name: "y"},
		"pick": {file: "lib/a.js", name: "pick"},
		"b":    {file: "lib/b.ts", name: "default"},
		"d":    {file: "lib/b.ts", name: "default"},
		"e":    {file: "lib/b.ts", name: "e"},
		"ff":   {file: "lib/b.ts", name: "f"},
		"ns":   {file: "lib/c/index.js", name: "*"},
	}
	if !reflect.DeepEqual(m.imports, want) {
		t.Errorf("imports = %v, want %v", m.imports, want)
	}
	wantExports := map[string]string{"router": "router", "make": "makeRouter", "extra": "other"}
	if !reflect.DeepEqual(m.exports, wantExports) {
		t.Errorf("exports = %v, want %v", m.exports, wantExports)
	}
}

func TestJSModuleExportsAndFactories(t *testing.T) {
	root := writeTree(t, map[string]string{
		"esm.ts": `export default router;
export function createA(deps: Deps): Router {
  const r = Router();
  return r;
}
export const createB = async ({ store }: Deps): Promise<Router> => {
  return Router();
};
const inner = 1;
export { inner as renamed };
export { thing } from './other';
`,
		"other.ts": "export const thing = 1;\n",
		"cjs.js": `module.exports = (deps) => {
  const router = express.Router();
  return router;
};
`,
		"named.js": `exports.createC = function (deps) {
  return x;
};
module.exports.createD = (deps) => {
  return y;
};
`,
	})
	esm := readJSModule(root, "esm.ts")
	for name, local := range map[string]string{"default": "router", "createA": "createA", "createB": "createB", "renamed": "inner"} {
		if esm.exports[name] != local {
			t.Errorf("esm export %s = %q, want %q", name, esm.exports[name], local)
		}
	}
	if got := esm.reexports["thing"]; got != (jsImport{file: "other.ts", name: "thing"}) {
		t.Errorf("re-export thing = %v", got)
	}
	if fn, ok := esm.funcs["createA"]; !ok || fn.start != 2 || fn.end != 5 {
		t.Errorf("createA body = %+v, %v; want lines 2-5", fn, ok)
	}
	if fn, ok := esm.funcs["createB"]; !ok || fn.start != 6 || fn.end != 8 {
		t.Errorf("createB body = %+v, %v; want lines 6-8", fn, ok)
	}
	cjs := readJSModule(root, "cjs.js")
	if cjs.exports["default"] != jsDefaultFn || cjs.funcs[jsDefaultFn].end != 4 {
		t.Errorf("cjs default factory: exports %v funcs %v", cjs.exports, cjs.funcs)
	}
	named := readJSModule(root, "named.js")
	for _, name := range []string{"createC", "createD"} {
		if named.exports[name] != name {
			t.Errorf("named export %s missing: %v", name, named.exports)
		}
		if _, ok := named.funcs[name]; !ok {
			t.Errorf("named factory %s has no body", name)
		}
	}
}

func TestJSResolveModule(t *testing.T) {
	root := writeTree(t, map[string]string{
		"src/routes/index.ts": "",
		"src/routes/user.js":  "",
		"src/app.ts":          "",
	})
	cases := map[string]string{
		"./routes":          "src/routes/index.ts",
		"./routes/index.js": "src/routes/index.ts",
		"./routes/user":     "src/routes/user.js",
		"../src/app":        "src/app.ts",
		"express":           "",
		"@/routes":          "",
		"../../outside":     "",
		"./missing":         "",
	}
	for spec, want := range cases {
		if got := jsResolveModule(root, "src/app.ts", spec); got != want {
			t.Errorf("jsResolveModule(%q) = %q, want %q", spec, got, want)
		}
	}
}

// TestJSScopesIgnoreObjectBraces: an object literal's closing brace used to
// close the enclosing function, so a router declared in a factory stopped
// being visible a few lines later.
func TestJSScopesIgnoreObjectBraces(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "r.ts")
	src := `function createRouter({ store }) {
  const router = express.Router();
  router.use(auth({ store, options: { strict: true } }));
  router.get('/a', h);
  return router;
}
export function typed(deps: Deps): Router {
  const r = Router();
  return r;
}
`
	if err := os.WriteFile(path, []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
	scopes := jsFileScopes(path)
	want := []lineScope{{start: 1, end: 6}, {start: 7, end: 10}}
	if !reflect.DeepEqual(scopes, want) {
		t.Errorf("scopes = %v, want %v", scopes, want)
	}
}
