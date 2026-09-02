// Package web provides the embedded admin GUI for the standalone server.
package web

import (
	"embed"
	"io/fs"
	"net/http"
)

//go:embed static
var staticFiles embed.FS

// Handler returns an http.Handler that serves the embedded GUI files.
// For SPA routing, it falls back to index.html for unknown paths.
func Handler() http.Handler {
	sub, _ := fs.Sub(staticFiles, "static")
	return spaHandler{fs: http.FS(sub)}
}

// spaHandler serves static files and falls back to index.html for SPA routes.
type spaHandler struct {
	fs http.FileSystem
}

func (h spaHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Disable browser caching of the GUI shell. The collector ships a fresh
	// app.js / index.html with every release; without this, Chrome's
	// heuristic cache held on to the old script tag (`type="module"`) even
	// after a hard reload, so users hit "nothing happens when I click"
	// because they were running stale JS. The whole bundle is < 100 KB so
	// the no-store cost is negligible.
	w.Header().Set("Cache-Control", "no-store, must-revalidate")
	w.Header().Set("Pragma", "no-cache")

	// Try to serve the requested file
	f, err := h.fs.Open(r.URL.Path)
	if err != nil {
		// Fall back to index.html for SPA routing
		r.URL.Path = "/"
	} else {
		f.Close()
	}
	http.FileServer(h.fs).ServeHTTP(w, r)
}
