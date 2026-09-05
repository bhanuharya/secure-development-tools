// Command sdt is the Secure Development Tools CLI entry point.
package main

import (
	"errors"
	"fmt"
	"os"

	"github.com/bhanuharya/secure-development-tools/internal/app"
)

func main() {
	root := app.NewRoot()
	// Cobra completion (P2) is available via `sdt completion`.
	if err := root.Execute(); err != nil {
		var ee *app.ExitError
		if errors.As(err, &ee) {
			fmt.Fprintln(os.Stderr, "sdt: "+ee.Msg)
			os.Exit(ee.Code)
		}
		fmt.Fprintln(os.Stderr, "sdt: "+err.Error())
		os.Exit(app.ExitInternalError)
	}
}
