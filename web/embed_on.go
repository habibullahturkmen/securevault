//go:build embedui

// Package webui embeds the production frontend build into the server binary.
// Production builds (make build, Dockerfile) run `pnpm build` first and
// compile with -tags embedui, so the binary carries the entire interface.
package webui

import (
	"embed"
	"io/fs"
)

//go:embed all:dist
var dist embed.FS

// FS returns the built web interface rooted at its index.html.
func FS() fs.FS {
	sub, err := fs.Sub(dist, "dist")
	if err != nil {
		panic("webui: dist not embedded: " + err.Error())
	}
	return sub
}
