// SPDX-License-Identifier: Apache-2.0

// Package ui embeds the built web UI. The build copies apps/mydc-web/web/dist
// into ./dist before `go build`; without it the daemon serves a notice page.
package ui

import (
	"embed"
	"io/fs"
)

//go:embed all:dist
var dist embed.FS

// FS returns the UI files rooted at dist, or nil when no build is embedded.
func FS() fs.FS {
	sub, err := fs.Sub(dist, "dist")
	if err != nil {
		return nil
	}
	if _, err := fs.Stat(sub, "index.html"); err != nil {
		return nil
	}
	return sub
}
