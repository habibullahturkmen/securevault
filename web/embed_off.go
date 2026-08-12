//go:build !embedui

// Package webui embeds the production frontend build into the server binary.
// In development builds (plain `go run`) nothing is embedded: the Vite dev
// server serves the interface with hot reload and proxies /api here.
package webui

import "io/fs"

// FS returns nil: no embedded interface in this build.
func FS() fs.FS { return nil }
