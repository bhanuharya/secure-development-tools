package endpoints

import (
	"reflect"
	"testing"
)

// TestPyImports pins the import forms the cross-file mount linking reads.
func TestPyImports(t *testing.T) {
	root := writeTree(t, map[string]string{
		"src/app/__init__.py":         "",
		"src/app/routers/__init__.py": "",
		"src/app/routers/users.py":    "router = None\n",
		"src/app/routers/orders.py":   "router = None\n",
		"src/app/api.py":              "api_router = None\n",
		"src/app/main.py": `from app.routers.users import router as users_router
from .api import api_router
from app.routers import orders  # a submodule, used as orders.router
from app.routers.users import (
    router as users_again,
)
import app.routers.orders as orders_mod
from fastapi import FastAPI
`,
	})
	p := newPyProject(root)
	got := p.importsOf("src/app/main.py")
	want := map[string]pyImport{
		"users_router": {file: "src/app/routers/users.py", name: "router"},
		"api_router":   {file: "src/app/api.py", name: "api_router"},
		"orders":       {file: "src/app/routers/orders.py"},
		"users_again":  {file: "src/app/routers/users.py", name: "router"},
		"orders_mod":   {file: "src/app/routers/orders.py"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("imports = %v\nwant %v", got, want)
	}
	for expr, wantFile := range map[string]string{"users_router": "src/app/routers/users.py", "orders.router": "src/app/routers/orders.py", "FastAPI": ""} {
		if file, _ := p.resolveTarget("src/app/main.py", expr); file != wantFile {
			t.Errorf("resolveTarget(%q) = %q, want %q", expr, file, wantFile)
		}
	}
}
