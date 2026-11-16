package legacy

import (
	"net/http"

	"github.com/go-chi/chi/v5"
)

// chi panics on a pattern without a leading slash, so this one stays
// unresolved rather than becoming /status.
func Mount(r chi.Router) {
	r.Get("status", status)
}

func status(w http.ResponseWriter, r *http.Request) {}
