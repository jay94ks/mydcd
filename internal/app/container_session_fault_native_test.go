// SPDX-License-Identifier: Apache-2.0

package app

import (
	"encoding/json"
	"io"
	"net/http"
	"path"
	"strings"
	"sync"
)

// This gate is installed only on the owned fixture's explicit Engine UDS.
// It forwards the real ExecCreate and once loses an actual 101 start response.
// It neither simulates native success nor sends a second start to recover it.
type managedExecReplyFault struct {
	mu              sync.Mutex
	native          string
	ids             map[string]bool
	creates, starts uint64
	dropped         bool
}

func (f *managedExecReplyFault) arm(native string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.native, f.creates, f.starts, f.dropped = native, 0, 0, false
	f.ids = map[string]bool{}
}
func (f *managedExecReplyFault) disarm() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.native = ""
}
func (f *managedExecReplyFault) snapshot() (uint64, uint64, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.creates, f.starts, f.dropped
}

func (f *managedExecReplyFault) serve(proxy *managedCreateReplyFault, w http.ResponseWriter, request *http.Request) {
	f.mu.Lock()
	create := f.native != "" && request.Method == http.MethodPost && strings.Contains(request.URL.Path, "/containers/") && path.Base(request.URL.Path) == "exec" && path.Base(path.Dir(request.URL.Path)) == f.native
	start := request.Method == http.MethodPost && strings.Contains(request.URL.Path, "/exec/") && path.Base(request.URL.Path) == "start" && f.ids[path.Base(path.Dir(request.URL.Path))]
	drop := start && !f.dropped
	if create {
		f.creates++
	}
	if start {
		f.starts++
	}
	f.mu.Unlock()
	if !create && !drop {
		proxy.forward.ServeHTTP(w, request)
		return
	}
	upstream := request.Clone(request.Context())
	upstream.RequestURI = ""
	upstream.URL.Scheme, upstream.URL.Host = "http", "docker"
	response, err := proxy.transport.RoundTrip(upstream)
	if err != nil {
		http.Error(w, "owned exec upstream unavailable", http.StatusBadGateway)
		return
	}
	defer response.Body.Close()
	if drop && response.StatusCode == http.StatusSwitchingProtocols {
		// The Engine accepted the actual start. Close only the stream while
		// withholding its response from the SDK; Inspect must recover the ID.
		f.mu.Lock()
		f.dropped = true
		f.mu.Unlock()
		conn, _, err := w.(http.Hijacker).Hijack()
		if err == nil {
			_ = conn.Close()
		}
		return
	}
	raw, err := io.ReadAll(io.LimitReader(response.Body, (64<<10)+1))
	if err != nil || len(raw) > 64<<10 {
		http.Error(w, "owned exec response bounds", http.StatusBadGateway)
		return
	}
	if create && response.StatusCode == http.StatusCreated {
		var created struct{ ID string }
		if json.Unmarshal(raw, &created) == nil && created.ID != "" {
			f.mu.Lock()
			f.ids[created.ID] = true
			f.mu.Unlock()
		}
	}
	for key, values := range response.Header {
		for _, value := range values {
			w.Header().Add(key, value)
		}
	}
	w.WriteHeader(response.StatusCode)
	_, _ = w.Write(raw)
}
