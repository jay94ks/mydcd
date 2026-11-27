// SPDX-License-Identifier: Apache-2.0

package ingress

import (
	"net/http"
	"net/netip"
	"strings"
)

// NodeEnrollPath is where a new VPS server fetches sfcd and enrolls
// (devel/design/vps-nodes.md §4). On HTTPS, for a host this ingress serves,
// it goes to the cluster's handler ahead of every app route; an app route
// for it is ignored. With no handler set it answers 404.
const NodeEnrollPath = "/.well-known/sfc/node/"

// NodeEnrollHandler serves one enrollment request. source is the client
// address the connection came from; the handler decides by it alone, so
// it is never taken from a header.
type NodeEnrollHandler func(w http.ResponseWriter, r *http.Request, source netip.Addr)

type nodeEnroll struct{ serve NodeEnrollHandler }

// SetNodeEnroll sets the handler (nil for none).
func (m *Manager) SetNodeEnroll(h NodeEnrollHandler) {
	m.enroll.Store(&nodeEnroll{serve: h})
}

func (m *Manager) nodeEnroll(r *http.Request) (NodeEnrollHandler, bool) {
	if !strings.HasPrefix(r.URL.Path, NodeEnrollPath) {
		return nil, false
	}
	e := m.enroll.Load()
	if r.TLS == nil || e == nil || e.serve == nil {
		return func(w http.ResponseWriter, r *http.Request, _ netip.Addr) { http.NotFound(w, r) }, true
	}
	return e.serve, true
}
