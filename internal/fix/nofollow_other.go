//go:build !unix

package fix

// There is no such flag here: writeNoFollow looks at the path before it opens it.
const openNoFollow = 0
