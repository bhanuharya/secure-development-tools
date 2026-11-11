// Package endpoints builds an inventory of HTTP routes and the access-control
// protection each one effectively has (SPEC §3). Facts come from Opengrep
// rules under rules/endpoint-facts/; resolvers turn them into routes.
package endpoints

// Schema is the inventory document version.
const Schema = "sdt-endpoints/v1"

// Protection is the effective access control of a route.
type Protection string

const (
	ProtPublic        Protection = "public"
	ProtAuthenticated Protection = "authenticated"
	ProtRole          Protection = "role"
	ProtDenied        Protection = "denied"
	ProtUnknown       Protection = "unknown"
)

// Route is one registered endpoint and what protects it.
type Route struct {
	Service    string     `json:"service"`   // dir of the nearest module file, relative; "." for the root
	Framework  string     `json:"framework"` // gin, echo, ... (T02: gin only)
	Method     string     `json:"method"`    // GET POST PUT PATCH DELETE ANY
	Path       string     `json:"path"`      // full path, params as {name}
	Handler    string     `json:"handler"`   // as written: handler.CreateOrder
	File       string     `json:"file"`
	Line       int        `json:"line"`
	Protection Protection `json:"protection"`
	Roles      []string   `json:"roles,omitempty"` // for "role"
	// Evidence is "file:line what decided it", most important first.
	Evidence   []string `json:"evidence"`
	Confidence string   `json:"confidence"` // high | medium | low
}

// Inventory is the document `sdt endpoints` writes.
type Inventory struct {
	Schema     string         `json:"schema"`
	Root       string         `json:"root"`
	Routes     []Route        `json:"routes"`
	Summary    map[string]int `json:"summary"`
	Unresolved []string       `json:"unresolved,omitempty"`
}
