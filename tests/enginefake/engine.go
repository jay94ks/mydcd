// SPDX-License-Identifier: Apache-2.0

// Package enginefake is an in-memory Docker Engine API on a Unix socket for
// tests that run real mydcd nodes without Docker (devel/refactor/16). Product
// packages never import it.
//
// Containers run no process: start makes them running, stop makes them
// exited, and the test sets exit codes and log lines. With Host (root) a
// running container still gets its own network namespace, held by a
// sleeping process, on a real kernel bridge (host_linux.go). Volume mountpoints are
// real directories under the engine's root so mydcd can open volume data.
// An API the fake does not know answers 501 and is recorded; Unknown lists
// those calls so a test can fail on them.
package enginefake

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"sync"
	"time"

	dockerspec "github.com/moby/docker-image-spec/specs-go/v1"
)

// APIVersion is the Engine API version the fake reports.
const APIVersion = "1.51"

// Engine is one fake Docker daemon.
type Engine struct {
	root     string
	listener net.Listener
	server   *http.Server

	mu         sync.Mutex
	containers map[string]*ctr
	images     map[string]*img
	volumes    map[string]*vol
	networks   map[string]*netw
	execs      map[string]*execProcess
	unknown    []string
	remote     map[string]dockerspec.DockerOCIImage // pullable, by reference
	pulls      []string
	watchers   map[chan event]struct{}
	// host makes kernel bridges and container namespaces, as Docker does
	// (needs root; see host_linux.go and UseHost). Close removes what is
	// left. hostNetNS is the node's network namespace for the bridges.
	host      bool
	hostNetNS string
	// NCPU and MemTotal are what /info reports.
	NCPU     int
	MemTotal int64
}

// Start serves a fake engine at root/docker.sock. Volume data lives under
// root/volumes. Close stops it.
func Start(root string) (*Engine, error) {
	if err := os.MkdirAll(filepath.Join(root, "volumes"), 0o711); err != nil {
		return nil, err
	}
	socket := filepath.Join(root, "docker.sock")
	l, err := net.Listen("unix", socket)
	if err != nil {
		return nil, err
	}
	e := &Engine{root: root, listener: l, containers: map[string]*ctr{}, images: map[string]*img{}, volumes: map[string]*vol{}, networks: map[string]*netw{}, execs: map[string]*execProcess{}, watchers: map[chan event]struct{}{}, remote: map[string]dockerspec.DockerOCIImage{}, NCPU: 4, MemTotal: 8 << 30}
	for _, n := range []string{"bridge", "host", "none"} {
		id := newID()
		e.networks[id] = &netw{ID: id, Name: n, Driver: map[string]string{"bridge": "bridge", "host": "host", "none": "null"}[n], Created: time.Now().UTC(), Options: map[string]string{}, Labels: map[string]string{}, Endpoints: map[string]endpoint{}}
	}
	e.server = &http.Server{Handler: http.HandlerFunc(e.serve), ReadHeaderTimeout: 10 * time.Second}
	go func() { _ = e.server.Serve(l) }()
	return e, nil
}

// Endpoint is the unix:// endpoint for a node's docker_socket.
func (e *Engine) Endpoint() string { return "unix://" + e.listener.Addr().String() }

// Root is the engine's data directory (reported as DockerRootDir).
func (e *Engine) Root() string { return e.root }

// Close stops serving and ends event streams.
func (e *Engine) Close() error {
	e.mu.Lock()
	for _, c := range e.containers {
		e.stopSandbox(c)
	}
	for _, n := range e.networks {
		e.deleteBridgeLink(n)
	}
	for ch := range e.watchers {
		close(ch)
		delete(e.watchers, ch)
	}
	e.mu.Unlock()
	return e.server.Close()
}

// Unknown lists the calls the fake answered with 501, in order.
func (e *Engine) Unknown() []string {
	e.mu.Lock()
	defer e.mu.Unlock()
	return slices.Clone(e.unknown)
}

var versionPrefix = regexp.MustCompile(`^/v1\.[0-9]+/`)

func (e *Engine) serve(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Api-Version", APIVersion)
	w.Header().Set("Server", "enginefake")
	path := versionPrefix.ReplaceAllString(r.URL.Path, "/")
	parts := strings.Split(strings.Trim(path, "/"), "/")
	for _, h := range routes {
		if h.method != "" && h.method != r.Method && (h.method != "GET" || r.Method != "HEAD") {
			continue
		}
		if args, ok := h.match(parts); ok {
			h.fn(e, w, r, args)
			return
		}
	}
	e.mu.Lock()
	e.unknown = append(e.unknown, r.Method+" "+path)
	e.mu.Unlock()
	writeError(w, http.StatusNotImplemented, "enginefake: "+r.Method+" "+path+" is not implemented")
}

type route struct {
	method  string
	pattern []string // "*" matches one segment; a trailing "**" matches the rest
	fn      func(*Engine, http.ResponseWriter, *http.Request, []string)
}

func (h route) match(parts []string) ([]string, bool) {
	var args []string
	for i, p := range h.pattern {
		if p == "**" {
			if i >= len(parts) {
				return nil, false
			}
			return append(args, strings.Join(parts[i:], "/")), true
		}
		if i >= len(parts) {
			return nil, false
		}
		switch p {
		case "*":
			args = append(args, parts[i])
		default:
			if parts[i] != p {
				return nil, false
			}
		}
	}
	return args, len(parts) == len(h.pattern)
}

var routes []route

func handle(method, pattern string, fn func(*Engine, http.ResponseWriter, *http.Request, []string)) {
	routes = append(routes, route{method: method, pattern: strings.Split(strings.Trim(pattern, "/"), "/"), fn: fn})
}

func init() {
	handle("GET", "/_ping", func(e *Engine, w http.ResponseWriter, r *http.Request, _ []string) {
		w.Header().Set("Content-Type", "text/plain")
		if r.Method != "HEAD" {
			_, _ = w.Write([]byte("OK"))
		}
	})
	handle("GET", "/version", (*Engine).version)
	handle("GET", "/info", (*Engine).info)
	handle("GET", "/events", (*Engine).events)
	containerRoutes()
	volumeRoutes()
	networkRoutes()
	imageRoutes()
	execRoutes()
}

func (e *Engine) version(w http.ResponseWriter, _ *http.Request, _ []string) {
	writeJSON(w, http.StatusOK, map[string]any{"Version": "27.0.0-enginefake", "ApiVersion": APIVersion, "MinAPIVersion": "1.24", "Os": "linux", "Arch": "amd64", "KernelVersion": "6.0.0", "GitCommit": "enginefake"})
}

func (e *Engine) info(w http.ResponseWriter, _ *http.Request, _ []string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	running := 0
	for _, c := range e.containers {
		if c.State.Running {
			running++
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"ID": "enginefake", "Name": "enginefake", "Containers": len(e.containers), "ContainersRunning": running, "Images": len(e.images), "Driver": "overlay2", "NCPU": e.NCPU, "MemTotal": e.MemTotal, "DockerRootDir": e.root, "OperatingSystem": "enginefake", "OSType": "linux", "Architecture": "x86_64", "ServerVersion": "27.0.0-enginefake", "CgroupDriver": "systemd", "CgroupVersion": "2"})
}

// event is one /events message.
type event struct {
	Type   string `json:"Type"`
	Action string `json:"Action"`
	Actor  struct {
		ID         string            `json:"ID"`
		Attributes map[string]string `json:"Attributes"`
	} `json:"Actor"`
	Scope    string `json:"scope"`
	Time     int64  `json:"time"`
	TimeNano int64  `json:"timeNano"`
}

// emit sends an event to every stream. The caller holds e.mu.
func (e *Engine) emit(kind, action, id string, attrs map[string]string) {
	now := time.Now()
	ev := event{Type: kind, Action: action, Scope: "local", Time: now.Unix(), TimeNano: now.UnixNano()}
	ev.Actor.ID = id
	ev.Actor.Attributes = map[string]string{}
	for k, v := range attrs {
		ev.Actor.Attributes[k] = v
	}
	for ch := range e.watchers {
		select {
		case ch <- ev:
		default: // a slow reader misses events, as with a lagging daemon
		}
	}
}

func (e *Engine) events(w http.ResponseWriter, r *http.Request, _ []string) {
	f, err := parseFilters(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	ch := make(chan event, 256)
	e.mu.Lock()
	e.watchers[ch] = struct{}{}
	e.mu.Unlock()
	defer func() {
		e.mu.Lock()
		if _, ok := e.watchers[ch]; ok {
			delete(e.watchers, ch)
			close(ch)
		}
		e.mu.Unlock()
	}()
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	flusher, _ := w.(http.Flusher)
	if flusher != nil {
		flusher.Flush()
	}
	enc := json.NewEncoder(w)
	for {
		select {
		case <-r.Context().Done():
			return
		case ev, ok := <-ch:
			if !ok {
				return
			}
			if !f.matchEvent(ev) {
				continue
			}
			if enc.Encode(ev) != nil {
				return
			}
			if flusher != nil {
				flusher.Flush()
			}
		}
	}
}

// filters is the Engine API filters query (map of term to set of values).
type filters map[string]map[string]bool

func parseFilters(r *http.Request) (filters, error) {
	f := filters{}
	raw := r.URL.Query().Get("filters")
	if raw == "" {
		return f, nil
	}
	if err := json.Unmarshal([]byte(raw), &f); err != nil {
		// Old clients send term -> list.
		var list map[string][]string
		if json.Unmarshal([]byte(raw), &list) != nil {
			return nil, fmt.Errorf("filters: %w", err)
		}
		for k, vs := range list {
			f[k] = map[string]bool{}
			for _, v := range vs {
				f[k][v] = true
			}
		}
	}
	return f, nil
}

func (f filters) values(term string) []string {
	var out []string
	for v, ok := range f[term] {
		if ok {
			out = append(out, v)
		}
	}
	return out
}

// labels reports whether labels match every label filter ("k" or "k=v").
func (f filters) labels(labels map[string]string) bool {
	for _, want := range f.values("label") {
		k, v, hasValue := strings.Cut(want, "=")
		got, ok := labels[k]
		if !ok || hasValue && got != v {
			return false
		}
	}
	return true
}

// oneOf reports whether value matches one of term's values (no filter: true).
func (f filters) oneOf(term string, match func(string) bool) bool {
	vs := f.values(term)
	if len(vs) == 0 {
		return true
	}
	return slices.ContainsFunc(vs, match)
}

func (f filters) matchEvent(ev event) bool {
	return f.oneOf("type", func(v string) bool { return v == ev.Type }) &&
		f.oneOf("event", func(v string) bool { return v == ev.Action }) &&
		f.labels(ev.Actor.Attributes)
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, code int, msg string) {
	writeJSON(w, code, map[string]string{"message": msg})
}

func readJSON(r *http.Request, v any) error {
	if r.Body == nil {
		return nil
	}
	d := json.NewDecoder(r.Body)
	if err := d.Decode(v); err != nil && err.Error() != "EOF" {
		return err
	}
	return nil
}

func newID() string {
	var b [32]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

func digestOf(b []byte) string {
	d := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(d[:])
}

func stamp(t time.Time) string { return t.UTC().Format(time.RFC3339Nano) }
