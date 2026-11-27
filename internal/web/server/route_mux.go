// SPDX-License-Identifier: Apache-2.0

package server

import "net/http"

// routeMux is the screen API mux. It remembers every pattern so the
// coordinator's tool catalog can be checked against the routes that exist
// (R19): a tool must name a registered route, and every route is either a
// tool or listed in aiHidden with its reason.
type routeMux struct {
	*http.ServeMux
	patterns []string
}

func newRouteMux() *routeMux { return &routeMux{ServeMux: http.NewServeMux()} }

func (m *routeMux) HandleFunc(pattern string, h func(http.ResponseWriter, *http.Request)) {
	m.patterns = append(m.patterns, pattern)
	m.ServeMux.HandleFunc(pattern, h)
}
