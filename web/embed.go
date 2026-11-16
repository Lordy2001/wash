// Package webui embeds the browser client (static/).
package webui

import (
	"embed"
	"io/fs"
)

//go:embed static
var files embed.FS

// Static is the site root.
func Static() fs.FS {
	sub, _ := fs.Sub(files, "static")
	return sub
}
