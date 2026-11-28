// SPDX-License-Identifier: Apache-2.0

// Package remote keeps the Volumes that tasks on this server use from their
// home over SFCP VolumeFS: one local FUSE mount per remote consumer, held
// while the task needs it and while the engine still has a clone of it.
//
// The order is the task's: Hold before the container is created, Bind once
// it exists, BeginStart/EndStart around the engine Start, the engine's Mount
// and Unmount take and drop holds by mount_id, and Release only after the
// container is proven gone. Gone is signed only after Release.
//
// Every step is journaled before it is acted on, so a restarted sfcd knows
// each consumer it held, whether a Start outcome is unknown, and what it
// still has to release. Mounts are attached again on demand.
package remote

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"sort"
	"strconv"
	"sync"

	"github.com/jay94ks/seafield/internal/storage"
	"github.com/jay94ks/seafield/internal/workload/volumes"
)

var (
	// ErrUnknown: name is not a remote volume of a task on this server.
	ErrUnknown = errors.New("remote volume: unknown")
	// ErrNotBound: the volume is held but not for this container.
	ErrNotBound = errors.New("remote volume: not this container")
	// ErrHeld: the consumer is already held with a different spec.
	ErrHeld = errors.New("remote volume: held with another spec")
	// ErrStarting: another writer's Start is in progress (or its outcome is
	// unknown) on this server.
	ErrStarting = errors.New("remote volume: another writer start in progress")
	// ErrNotReleased: the consumer still has a mount or an unsettled Start.
	ErrNotReleased = errors.New("remote volume: not released")
)

// Spec is one remote consumer of a shared Volume on this server.
type Spec struct {
	Scope    volumes.Scope
	Consumer volumes.Consumer
	// Home is the current key of the Volume's owner (the server to dial).
	Home [32]byte
}

// Name is the engine volume name of the consumer: stable across restarts,
// distinct per Volume generation and consumer.
func (s Spec) Name() string {
	sum := sha256.Sum256([]byte(s.Scope.Key() + "\x00" + hex.EncodeToString(s.Scope.Cluster[:]) + "\x00" + strconv.FormatUint(s.Scope.Generation, 10) + "\x00" + s.Consumer.ID))
	return "sfc-remote-" + hex.EncodeToString(sum[:16])
}

// Ref is what the runner asks the home to mount (Server Authorize volume).
func (s Spec) Ref() MountRef { return MountRef{Scope: s.Scope, Consumer: s.Consumer.ID} }

// Attached is a live local mount of a remote Volume.
type Attached struct {
	// Dir is the FUSE mount point the engine's Mount answer opens.
	Dir string
	// Detach unmounts and ends the VolumeFS mount on the home.
	Detach func() error
	// abandon stops serving as a crash would (tests).
	abandon func()
}

// Attach mounts spec locally; Mounts calls it once per held consumer.
type Attach func(ctx context.Context, spec Spec) (Attached, error)

// record is the journal row of one consumer.
type record struct {
	Schema    uint8
	Spec      Spec
	Container string `json:",omitempty"`
	// Starting is set before a writer's engine Start and cleared only when
	// its outcome is known; while set no other writer starts here.
	Starting bool `json:",omitempty"`
	Released bool `json:",omitempty"`
}

// Mounts is this server's set of remote Volume mounts.
type Mounts struct {
	attach Attach
	db     *storage.DB // nil keeps the journal in memory (tests)

	mu       sync.Mutex
	records  map[string]record
	attached map[string]Attached
	holds    map[string]map[string]bool // engine mount_ids by name
}

const prefix = "remote-volume/"

// New keeps the journal in memory only.
func New(attach Attach) *Mounts {
	return &Mounts{attach: attach, records: map[string]record{}, attached: map[string]Attached{}, holds: map[string]map[string]bool{}}
}

// Open keeps the journal in db and loads what an earlier sfcd left.
func Open(db *storage.DB, attach Attach) (*Mounts, error) {
	m := New(attach)
	m.db = db
	rows, err := db.Scan(prefix)
	if err != nil {
		return nil, err
	}
	for key, raw := range rows {
		var r record
		if json.Unmarshal(raw, &r) != nil || r.Schema != 1 || prefix+r.Spec.Name() != key {
			return nil, errors.New("remote volume: bad journal row " + key)
		}
		m.records[r.Spec.Name()] = r
	}
	return m, nil
}

// save writes r (or deletes name when r is nil) before memory changes.
func (m *Mounts) save(name string, r *record) error {
	if m.db == nil {
		return nil
	}
	if r == nil {
		return m.db.Write(map[string][]byte{prefix + name: nil})
	}
	raw, err := json.Marshal(r)
	if err != nil {
		return err
	}
	return m.db.Write(map[string][]byte{prefix + name: raw})
}

// Hold journals spec and mounts it unless it is already, and returns the
// engine volume name.
func (m *Mounts) Hold(ctx context.Context, spec Spec) (string, error) {
	if !spec.Consumer.Remote() || spec.Home == ([32]byte{}) {
		return "", ErrUnknown
	}
	name := spec.Name()
	m.mu.Lock()
	r, ok := m.records[name]
	switch {
	case ok && r.Spec != spec:
		m.mu.Unlock()
		return "", ErrHeld
	case ok && r.Released:
		m.mu.Unlock()
		return "", ErrNotReleased // released consumers never mount again
	case !ok:
		r = record{Schema: 1, Spec: spec}
		if err := m.save(name, &r); err != nil {
			m.mu.Unlock()
			return "", err
		}
		m.records[name] = r
	}
	m.mu.Unlock()
	if _, err := m.ensure(ctx, name); err != nil {
		return "", err
	}
	return name, nil
}

// ensure attaches name if it is held and not attached yet.
func (m *Mounts) ensure(ctx context.Context, name string) (Attached, error) {
	m.mu.Lock()
	if at, ok := m.attached[name]; ok {
		m.mu.Unlock()
		return at, nil
	}
	r, ok := m.records[name]
	m.mu.Unlock()
	if !ok || r.Released {
		return Attached{}, ErrUnknown
	}
	// Attach dials the home and mounts; not under the lock.
	at, err := m.attach(ctx, r.Spec)
	if err != nil {
		return Attached{}, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if won, ok := m.attached[name]; ok {
		go func() { _ = at.Detach() }()
		return won, nil
	}
	if cur, ok := m.records[name]; !ok || cur.Released {
		go func() { _ = at.Detach() }()
		return Attached{}, ErrUnknown
	}
	m.attached[name] = at
	return at, nil
}

// Bind lets container mount name (after create; the ID is known only then).
func (m *Mounts) Bind(name, container string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	r, ok := m.records[name]
	switch {
	case !ok || r.Released:
		return ErrUnknown
	case r.Container == container:
		return nil
	case r.Container != "":
		return ErrNotBound
	}
	r.Container = container
	if err := m.save(name, &r); err != nil {
		return err
	}
	m.records[name] = r
	return nil
}

// BeginStart journals that the container of name is about to start. For a
// writer it refuses while another writer's Start here is unsettled.
func (m *Mounts) BeginStart(name string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	r, ok := m.records[name]
	if !ok || r.Released || r.Container == "" {
		return ErrUnknown
	}
	if !r.Spec.Consumer.Writable || r.Starting {
		return nil
	}
	for other, o := range m.records {
		if other != name && o.Starting && !o.Released {
			return ErrStarting
		}
	}
	r.Starting = true
	if err := m.save(name, &r); err != nil {
		return err
	}
	m.records[name] = r
	return nil
}

// EndStart settles a Start whose outcome is known: it ran, or it provably
// never did (inspect). An unknown outcome is not settled here; the record
// keeps Starting until such evidence comes.
func (m *Mounts) EndStart(name string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	r, ok := m.records[name]
	if !ok || !r.Starting {
		return nil
	}
	r.Starting = false
	if err := m.save(name, &r); err != nil {
		return err
	}
	m.records[name] = r
	return nil
}

// EngineMountDir is the engine's Mount: name's mount point when container is
// the one bound to it, holding it for mountID. After an sfcd restart the
// mount is attached again here.
func (m *Mounts) EngineMountDir(ctx context.Context, name, mountID, container string) (string, bool, bool, error) {
	m.mu.Lock()
	r, ok := m.records[name]
	m.mu.Unlock()
	if !ok || r.Released {
		return "", false, false, nil
	}
	if r.Container == "" || r.Container != container {
		return "", false, true, ErrNotBound
	}
	at, err := m.ensure(ctx, name)
	if err != nil {
		return "", false, true, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.holds[name] == nil {
		m.holds[name] = map[string]bool{}
	}
	m.holds[name][mountID] = true
	return at.Dir, !r.Spec.Consumer.Writable, true, nil
}

// EngineUnmounted is the engine's Unmount (or a Mount answer that failed).
func (m *Mounts) EngineUnmounted(name, mountID string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.holds[name], mountID)
}

// EngineVolumeNames lists the names of held, unreleased consumers.
func (m *Mounts) EngineVolumeNames() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := []string{}
	for name, r := range m.records {
		if !r.Released {
			out = append(out, name)
		}
	}
	sort.Strings(out)
	return out
}

// Held reports whether name is mounted here and how many engine holds it has.
func (m *Mounts) Held(name string) (bool, int) {
	m.mu.Lock()
	defer m.mu.Unlock()
	_, ok := m.attached[name]
	return ok, len(m.holds[name])
}

// Release is for a consumer whose container is proven gone (inspect found
// none): an unsettled Start is settled by that evidence, engine holds left
// by the gone container are dropped, the mount is detached and the record
// marked released. A failed detach keeps everything for a retry.
func (m *Mounts) Release(name string) error {
	m.mu.Lock()
	r, ok := m.records[name]
	at, attached := m.attached[name]
	m.mu.Unlock()
	if !ok || r.Released {
		return nil
	}
	if attached {
		if err := at.Detach(); err != nil {
			return err
		}
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.attached, name)
	delete(m.holds, name)
	r.Starting, r.Released = false, true
	if err := m.save(name, &r); err != nil {
		return err
	}
	m.records[name] = r
	return nil
}

// Gone signs the consumer's Gone with the runner's key once it is
// released. Only the runner named in the consumer may sign it.
func (m *Mounts) Gone(scope volumes.Scope, consumer volumes.Consumer, private ed25519.PrivateKey) (volumes.Gone, error) {
	name := Spec{Scope: scope, Consumer: consumer}.Name()
	m.mu.Lock()
	r, ok := m.records[name]
	m.mu.Unlock()
	key, valid := consumer.GoneKey()
	if !ok || r.Spec.Scope != scope || r.Spec.Consumer != consumer || !valid || len(private) != ed25519.PrivateKeySize || [32]byte(private.Public().(ed25519.PublicKey)) != key {
		return volumes.Gone{}, ErrUnknown
	}
	if !r.Released || r.Starting {
		return volumes.Gone{}, ErrNotReleased
	}
	g := volumes.Gone{Scope: scope, Consumer: consumer, Stopped: true, MountsGone: true}
	g.Signature = ed25519.Sign(private, volumes.GoneBytes(g))
	return g, nil
}

// Forget drops the record of a released consumer once Raft no longer has it.
func (m *Mounts) Forget(name string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if r, ok := m.records[name]; !ok || !r.Released {
		return ErrNotReleased
	}
	if err := m.save(name, nil); err != nil {
		return err
	}
	delete(m.records, name)
	return nil
}

// Released lists released records still kept (for Forget sweeps).
func (m *Mounts) Released() []Spec {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []Spec
	for _, r := range m.records {
		if r.Released {
			out = append(out, r.Spec)
		}
	}
	return out
}

// Close stops serving every mount without unmounting: requests already read
// are answered first, and the mounts stay in the FD store for the next sfcd
// (Resume). Without an FD store their containers see ENOTCONN.
func (m *Mounts) Close() {
	m.mu.Lock()
	all := m.attached
	m.attached = map[string]Attached{}
	m.mu.Unlock()
	for _, at := range all {
		if at.abandon != nil {
			at.abandon()
		}
	}
}

// ForgetGone drops the released records whose consumer gone says Raft no
// longer has (its Gone was applied); a later Gone could not be signed again
// and is not needed. It returns how many it dropped.
func (m *Mounts) ForgetGone(gone func(Spec) bool) int {
	n := 0
	for _, s := range m.Released() {
		if gone(s) && m.Forget(s.Name()) == nil {
			n++
		}
	}
	return n
}
