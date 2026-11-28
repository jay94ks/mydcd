// SPDX-License-Identifier: Apache-2.0

package app

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/jay94ks/seafield/internal/access"
	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/cluster/state"
	"github.com/jay94ks/seafield/internal/deployment"
	"github.com/jay94ks/seafield/internal/peercred"
	"github.com/jay94ks/seafield/internal/secrets"
	"github.com/jay94ks/seafield/internal/sfev"
)

// sfev.sock on this server (design: devel/proposals/sfev-sock.md). Each
// running container whose spec asks for a secret socket gets one
// sfev.Endpoint in its socket directory, anchored on the container's init
// process. Values are read only when the app asks (or a watch is open and
// the approved read-set changed), through the same quorum permit and holder
// reads as file inputs, filtered to the binding's socket grants. Nothing is
// kept after the one response.
type secretSockets struct {
	mu      sync.Mutex
	open    map[string]*secretSocket // workload task key
	running bool                     // secretSocketLoop started
}

type secretSocket struct {
	endpoint *sfev.Endpoint
	anchor   peercred.Process
	native   string
	pid      int
	// request is the task binding the values are read for; a renewal
	// replaces it without closing the connection (guarded by
	// secretSockets.mu).
	request control.AppBindingRequest
	// readSet is the last socket read-set this server's replica named;
	// a different one means a watch should read again.
	readSet [32]byte
	denied  bool
}

// errSocketPending: the binding no longer matches a committed secret
// revision and waits for its renewal; the app keeps what it has (503).
var errSocketPending = errors.New("secret socket renewal pending")

// syncSecretSocket opens, keeps or replaces task key's endpoint after a
// Step. Failures are logged and retried by the next pass; the container
// itself does not depend on its socket.
func (r *Runtime) syncSecretSocket(ctx context.Context, key string, request control.AppBindingRequest) {
	if r.workload == nil {
		return
	}
	anchor, ok, err := r.workload.SecretSocketAnchor(ctx, key)
	if err != nil || !ok {
		r.closeSecretSocket(key, "container not running")
		if err != nil {
			log.Printf("secret socket %s: %v", key, err)
		}
		return
	}
	r.secretSockets.mu.Lock()
	current := r.secretSockets.open[key]
	r.secretSockets.mu.Unlock()
	if current != nil && current.native == anchor.NativeID && current.pid == anchor.PID {
		if current.request.Task != request.Task || current.request.Digest != request.Digest {
			// Same container, renewed approval: the open watch reads the
			// new values and sends what changed.
			r.secretSockets.mu.Lock()
			current.request = request
			r.secretSockets.mu.Unlock()
			current.endpoint.Publish(sfev.Event{Kind: sfev.Changed})
		}
		return
	}
	r.closeSecretSocket(key, "container replaced")
	process, err := peercred.Open(anchor.PID)
	if err != nil {
		log.Printf("secret socket %s: pin init process: %v", key, err)
		return
	}
	// The PID is this container's only if the engine still names it now.
	again, ok, err := r.workload.SecretSocketAnchor(ctx, key)
	if err != nil || !ok || again != anchor || peercred.Alive(process.FD) != nil {
		_ = process.Close()
		log.Printf("secret socket %s: container changed while pinning it", key)
		return
	}
	s := &secretSocket{anchor: process, native: anchor.NativeID, pid: anchor.PID, request: request}
	endpoint, err := sfev.Open(sfev.Config{
		Name:   anchor.Name,
		Dir:    anchor.Dir,
		Anchor: process,
		UID:    process.UID,
		GID:    process.GID,
		Fetch: func(ctx context.Context) (sfev.Snapshot, error) {
			r.secretSockets.mu.Lock()
			current := s.request
			r.secretSockets.mu.Unlock()
			return r.secretSocketValues(ctx, current)
		},
	})
	if err != nil {
		_ = process.Close()
		log.Printf("secret socket %s: open: %v", key, err)
		return
	}
	s.endpoint = endpoint
	if v, err := r.Engine().Read(ctx, false); err == nil {
		s.readSet, s.denied = r.localSocketReadSet(v.State, request)
	}
	r.secretSockets.mu.Lock()
	if r.secretSockets.open == nil {
		r.secretSockets.open = map[string]*secretSocket{}
	}
	r.secretSockets.open[key] = s
	start := !r.secretSockets.running
	r.secretSockets.running = true
	r.secretSockets.mu.Unlock()
	if start {
		go r.secretSocketLoop()
	}
}

// closeSecretSocket ends key's endpoint (closing event to an open watch).
func (r *Runtime) closeSecretSocket(key, reason string) {
	r.secretSockets.mu.Lock()
	s := r.secretSockets.open[key]
	delete(r.secretSockets.open, key)
	r.secretSockets.mu.Unlock()
	if s == nil {
		return
	}
	_ = s.endpoint.Close()
	_ = s.anchor.Close()
	log.Printf("secret socket %s closed: %s", key, reason)
}

// retainSecretSockets closes the endpoints of tasks this server no longer
// runs (retired, replaced or moved away).
func (r *Runtime) retainSecretSockets(works []appWorkload) {
	keep := map[string]bool{}
	for _, w := range works {
		if w.step.Kind == "task" {
			keep[w.step.Key] = true
		}
	}
	r.secretSockets.mu.Lock()
	var gone []string
	for key := range r.secretSockets.open {
		if !keep[key] {
			gone = append(gone, key)
		}
	}
	r.secretSockets.mu.Unlock()
	for _, key := range gone {
		r.closeSecretSocket(key, "task no longer runs here")
	}
}

// closeSecretSockets ends every endpoint (sfcd stopping).
func (r *Runtime) closeSecretSockets() {
	r.secretSockets.mu.Lock()
	keys := make([]string, 0, len(r.secretSockets.open))
	for key := range r.secretSockets.open {
		keys = append(keys, key)
	}
	r.secretSockets.mu.Unlock()
	for _, key := range keys {
		r.closeSecretSocket(key, "sfcd stopping")
	}
}

// secretSocketLoop wakes on Raft applies, not on a timer: an endpoint hears
// Changed when its replica's socket read-set moved (a renewal, a new holder
// receipt) and Revoked when the approval no longer holds. Bursts of applies
// are coalesced; no value is read here.
func (r *Runtime) secretSocketLoop() {
	for {
		changed := r.Engine().Changes()
		select {
		case <-r.ctx.Done():
			r.closeSecretSockets()
			return
		case <-changed:
		}
		coalesce := time.NewTimer(200 * time.Millisecond)
		select {
		case <-r.ctx.Done():
			coalesce.Stop()
			r.closeSecretSockets()
			return
		case <-coalesce.C:
		}
		v, err := r.Engine().Read(r.ctx, false)
		if err != nil {
			continue
		}
		r.secretSockets.mu.Lock()
		open := make(map[string]*secretSocket, len(r.secretSockets.open))
		requests := make(map[string]control.AppBindingRequest, len(r.secretSockets.open))
		for key, s := range r.secretSockets.open {
			open[key], requests[key] = s, s.request
		}
		r.secretSockets.mu.Unlock()
		for key, s := range open {
			if peercred.Alive(s.anchor.FD) != nil {
				r.closeSecretSocket(key, "container stopped")
				continue
			}
			readSet, denied := r.localSocketReadSet(v.State, requests[key])
			switch {
			case denied && !s.denied:
				s.endpoint.Publish(sfev.Event{Kind: sfev.Revoked, Reason: "approval withdrawn"})
			case !denied && readSet != s.readSet:
				s.endpoint.Publish(sfev.Event{Kind: sfev.Changed})
			}
			s.readSet, s.denied = readSet, denied
		}
	}
}

// localSocketReadSet is the socket read-set this replica would permit now.
// denied is true only for a refusal that is not a pending renewal.
func (r *Runtime) localSocketReadSet(s state.State, request control.AppBindingRequest) ([32]byte, bool) {
	request.At = time.Now().Unix()
	permit, err := r.controlPolicy.AppBindingPermit(s, r.commandIdentity().Public, request)
	if err == nil {
		return permit.SocketReadSet, permit.SocketReadSet == ([32]byte{})
	}
	if r.controlPolicy.AppBindingRevisionChanged(s, request) {
		return [32]byte{}, false
	}
	return [32]byte{}, errors.Is(err, access.ErrDenied)
}

// secretSocketValues is one endpoint's Fetch: a fresh owner-only quorum
// permit, the holder reads of its socket grants, a final permit check, and
// the merged values in source order (a later source's key wins).
func (r *Runtime) secretSocketValues(ctx context.Context, request control.AppBindingRequest) (sfev.Snapshot, error) {
	request.At = time.Now().Unix()
	permit, err := r.appInputPermit(ctx, request)
	if err != nil {
		return sfev.Snapshot{}, r.secretSocketRefusal(ctx, request, err)
	}
	if permit.SocketReadSet == ([32]byte{}) {
		return sfev.Snapshot{}, sfev.ErrDenied
	}
	v, err := r.Engine().Read(ctx, false)
	if err != nil {
		return sfev.Snapshot{}, err
	}
	reads, err := r.controlPolicy.AppSocketReads(v.State, r.commandIdentity().Public, request, permit)
	if err != nil {
		return sfev.Snapshot{}, fmt.Errorf("local socket read set at index %d (permit %d): %w", v.State.Index(), permit.CommandIndex, err)
	}
	values := map[string][]byte{}
	defer func() {
		for _, data := range values {
			clear(data)
		}
	}()
	total := 0
	for _, read := range reads {
		var fetched []secrets.Fetched
		for _, leaf := range read.Plan.Leaves {
			profile, ok := leafProvider(read.Profiles, leaf)
			if !ok {
				return sfev.Snapshot{}, secrets.ErrProvider
			}
			q := control.AppInputFetch{Schema: 1, Consumer: r.commandIdentity().Public, Binding: request, ReadSet: permit.SocketReadSet, MinimumIndex: permit.CommandIndex, Realm: read.Realm, Secret: leaf.Secret}
			value, err := r.fetchAppInputLeaf(ctx, q, profile)
			if err != nil {
				clearFetched(fetched)
				return sfev.Snapshot{}, fmt.Errorf("read %s/%s: %w", read.Realm, leaf.Secret, err)
			}
			fetched = append(fetched, value)
		}
		merged, err := secrets.Merge(read.Plan, fetched, sfev.MaxValues)
		clearFetched(fetched)
		if err != nil {
			return sfev.Snapshot{}, errors.Join(sfev.ErrTooLarge, err)
		}
		for k, data := range merged.Values {
			if old, ok := values[k]; ok {
				total -= len(k) + len(old)
				clear(old)
			}
			values[k] = data
			total += len(k) + len(data)
		}
		if total > sfev.MaxValues {
			return sfev.Snapshot{}, sfev.ErrTooLarge
		}
	}
	request.At = time.Now().Unix()
	latest, err := r.appInputPermit(ctx, request)
	if err != nil {
		return sfev.Snapshot{}, r.secretSocketRefusal(ctx, request, err)
	}
	if latest.SocketReadSet != permit.SocketReadSet || latest.Task != permit.Task {
		return sfev.Snapshot{}, fmt.Errorf("socket permit changed during reads: %w", deployment.ErrInputs)
	}
	snap := sfev.Snapshot{Revision: socketRevision(permit.SocketReadSet), Values: make(map[string]string, len(values))}
	for k, data := range values {
		if !utf8.Valid(data) {
			// The socket speaks JSON strings; a binary value has no place
			// in it. Name only the key, never the value.
			return sfev.Snapshot{}, fmt.Errorf("secret key %q is not UTF-8 text: %w", k, sfev.ErrDenied)
		}
		snap.Values[k] = string(data)
	}
	return snap, nil
}

// secretSocketRefusal turns a refused permit into the socket's answer: a
// revision change waiting for its renewal keeps the connection (503); any
// other current refusal is a denial (403, and revocation of a watch).
func (r *Runtime) secretSocketRefusal(ctx context.Context, request control.AppBindingRequest, cause error) error {
	v, err := r.Engine().Read(ctx, false)
	if err != nil {
		return errors.Join(cause, err)
	}
	if r.controlPolicy.AppBindingRevisionChanged(v.State, request) {
		return errSocketPending
	}
	if _, err := r.controlPolicy.AppBindingPermit(v.State, r.commandIdentity().Public, request); errors.Is(err, access.ErrDenied) {
		return errors.Join(sfev.ErrDenied, cause)
	}
	return cause
}

// socketRevision names a socket read-set without exposing it.
func socketRevision(readSet [32]byte) string {
	sum := sha256.Sum256(append([]byte("sfc-secret-socket-revision-1\x00"), readSet[:]...))
	return hex.EncodeToString(sum[:16])
}

func clearFetched(values []secrets.Fetched) {
	for _, v := range values {
		for _, data := range v.Values {
			clear(data)
		}
	}
}
