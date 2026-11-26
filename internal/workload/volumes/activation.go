// SPDX-License-Identifier: Apache-2.0

package volumes

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"sync"

	cerrdefs "github.com/containerd/errdefs"
	"github.com/jay94ks/mydcd/internal/engine"
	"github.com/jay94ks/mydcd/internal/reconcile"
	"github.com/jay94ks/mydcd/internal/schema"
	"github.com/jay94ks/mydcd/internal/storage"
	"github.com/moby/moby/api/types/container"
	"github.com/moby/moby/api/types/mount"
	"github.com/moby/moby/client"
)

var ErrActivation = errors.New("original volume activation unavailable or unsettled")

type PermitAuthority func(context.Context, StartRequest) (Permit, error)

// Activation binds a shared consumer to one original local A2 operation. Task
// contains only public canonical workload metadata, never fetched secret data.
type Activation struct {
	TaskOwner        string `json:",omitempty"`
	Scope            Scope
	Consumer         Consumer
	NativeKey        string
	NativeGeneration uint64
	TaskKey          string
	Task             reconcile.Resource
	Operation        uint64
	NativeBinding    string `json:",omitempty"`
}
type activationBinding struct {
	Ref                               Activation
	NativeID                          string
	Lease                             NativeLease
	Started, Closed, Unsent, Released bool
	CreatePrepared                    bool         `json:",omitempty"`
	Exit                              *ProcessExit `json:",omitempty"`
	StopSent                          bool         `json:",omitempty"`
}
type activationRecord struct {
	Schema   uint8
	Scope    Scope
	Owner    Owner
	Gate     GateCheckpoint
	Bindings []activationBinding
}
type activationEntry struct {
	store *Activations
	mu    sync.Mutex
	disk  activationRecord
	gate  Gate
	scope Scope
	owner Owner
}
type Activations struct {
	retained            map[[32]byte]*Activations
	life                sync.RWMutex
	mu                  sync.Mutex
	db                  *storage.DB
	native              *NativeManager
	client              *engine.Client
	cluster, node, boot [32]byte
	authority           PermitAuthority
	entries             map[string]*activationEntry
	closed              bool
}

func validActivation(r Activation, cluster, node [32]byte) bool {
	return validTaskOwner(r) && validScope(r.Scope) && r.Scope.Cluster == cluster && validConsumer(r.Consumer, r.Scope) && r.Consumer.Owner.Key == node && r.Consumer.Generation == r.Task.Generation && r.NativeKey != "" && len(r.NativeKey) <= 512 && r.NativeGeneration > 0 && activationTask(r) && len(r.TaskKey) <= 512 && !strings.ContainsRune(r.TaskKey, 0) && r.Task.Present && r.Task.Spec != "" && len(r.Task.Spec) <= 64<<10 && r.Operation > 0
}

func activationTask(r Activation) bool {
	if r.Scope.RegistryManaged() {
		return false
	}
	if !r.Scope.TenantManaged() {
		return r.NativeBinding == "" && !fixedNativeKey(r.NativeKey) && strings.HasPrefix(r.TaskKey, "workload/task/"+r.Scope.Tenant+"/"+r.Scope.App+"/")
	}
	parts := strings.Split(r.TaskKey, "/")
	return validNativeID(r.NativeBinding) && r.NativeKey == FixedNativeKey(r.Scope) && r.NativeGeneration == r.Scope.Generation && r.Consumer.Owner.Native == FixedNativeName(r.Scope) && len(parts) == 5 && parts[0] == "workload" && parts[1] == "task" && parts[2] == r.Scope.Tenant && identifier(parts[3]) && identifier(parts[4])
}
func activationID(r Activation) string { return "activation/" + r.Consumer.ID }
func validNativeID(id string) bool {
	b, e := hex.DecodeString(id)
	return e == nil && len(b) == 32 && hex.EncodeToString(b) == id
}
func activationRecordKey(key string) string { return "activation/" + key }
func OpenActivations(path string, native *NativeManager, c *engine.Client, cluster, node [32]byte, authority PermitAuthority) (*Activations, error) {
	if native == nil || c == nil || native.driver.engine != c || c.Owner != engine.Owner(cluster, node) || cluster == ([32]byte{}) || node == ([32]byte{}) || authority == nil {
		return nil, ErrActivation
	}
	db, err := storage.Open(path)
	if err != nil {
		return nil, err
	}
	s := &Activations{db: db, native: native, client: c, cluster: cluster, node: node, authority: authority, entries: map[string]*activationEntry{}}
	ok := false
	defer func() {
		if !ok {
			_ = db.Close()
		}
	}()
	if _, err = rand.Read(s.boot[:]); err != nil {
		return nil, err
	}
	header, _ := json.Marshal(struct {
		Schema        uint8
		Cluster, Node [32]byte
	}{1, cluster, node})
	rows, err := db.Scan("")
	if err != nil {
		return nil, err
	}
	if len(rows) == 0 {
		if err = db.Write(map[string][]byte{"owner": header}); err != nil {
			return nil, err
		}
	} else if string(rows["owner"]) != string(header) {
		return nil, ErrActivation
	}
	writes := map[string][]byte{}
	for key, raw := range rows {
		if key == "owner" {
			continue
		}
		if !strings.HasPrefix(key, "activation/") {
			return nil, ErrActivation
		}
		disk, err := schema.Decode[activationRecord](raw)
		if err != nil || disk.Schema != 1 || !validScope(disk.Scope) || disk.Scope.Cluster != cluster || !validOwner(disk.Owner) || disk.Owner.Key != node || disk.Gate.Scope != disk.Scope || disk.Gate.Owner != disk.Owner || len(disk.Bindings) > 256 {
			return nil, ErrActivation
		}
		seen := map[string]bool{}
		starting := disk.Gate.Starting == nil
		for _, b := range disk.Bindings {
			r := b.Ref
			if !validActivation(r, cluster, node) || r.Scope != disk.Scope || r.Consumer.Owner != disk.Owner || activationRecordKey(r.Consumer.Owner.Native) != key || seen[r.Consumer.ID] || b.Lease.Key != r.NativeKey || b.Lease.Consumer != activationID(r) || b.Lease.Owner != disk.Owner || b.Lease.Scope != disk.Scope || b.Lease.Pin.Generation != r.NativeGeneration || b.Lease.Pin.Token == 0 && (b.NativeID != "" || b.Started) || b.NativeID != "" && !validNativeID(b.NativeID) || b.Started && b.NativeID == "" || b.Unsent && (!b.Closed || b.NativeID != "" || b.Started) || b.Released && !b.Closed || b.Closed && b.NativeID == "" && !b.Unsent || b.CreatePrepared && (b.NativeID != "" || b.Started || b.Closed || b.Unsent) {
				return nil, ErrActivation
			}
			if b.Exit != nil && (b.Unsent || b.CreatePrepared || b.NativeID == "" || !b.Exit.valid()) {
				return nil, ErrActivation
			}
			if b.StopSent && (b.NativeID == "" || b.Unsent || b.CreatePrepared) {
				return nil, ErrActivation
			}
			seen[r.Consumer.ID] = true
			if disk.Gate.Starting != nil && *disk.Gate.Starting == r.Consumer && b.NativeID != "" && !b.Closed {
				starting = true
			}
		}
		if !starting {
			return nil, ErrActivation
		}
		gate, err := RestoreGate(disk.Gate, s.boot)
		if err != nil {
			return nil, err
		}
		disk.Gate = gate.Checkpoint()
		encoded, _ := json.Marshal(disk)
		writes[key] = encoded
		if key != activationRecordKey(disk.Owner.Native) {
			return nil, ErrActivation
		}
		s.entries[disk.Owner.Native] = &activationEntry{store: s, disk: disk, gate: gate, scope: disk.Scope, owner: disk.Owner}
	}
	if len(writes) > 0 {
		if err = db.Write(writes); err != nil {
			return nil, err
		}
	}
	ok = true
	return s, nil
}
func (s *Activations) entry(r Activation, create bool) (*activationEntry, error) {
	if r.Consumer.Owner.Key != s.node {
		if owner := s.ownerStore(r.Consumer.Owner.Key); owner != nil {
			return owner.entry(r, create)
		}
		return nil, ErrActivation
	}
	if s.closed || !validActivation(r, s.cluster, s.node) {
		return nil, ErrActivation
	}
	s.mu.Lock()
	e := s.entries[r.Consumer.Owner.Native]
	s.mu.Unlock()
	if e == nil && create {
		native, err := s.native.View(r.NativeKey)
		if err != nil || !native.State.Applied.Present || native.State.Applied.Generation != r.NativeGeneration {
			return nil, ErrActivation
		}
		owner, scope, err := s.native.recordedOwner(r.NativeKey, native.State.Applied)
		if err != nil || scope != r.Scope || owner != r.Consumer.Owner {
			return nil, ErrActivation
		}
		if _, _, err = s.mountSource(r.NativeKey, r.Scope, r.Consumer.Owner, r.NativeGeneration, r.NativeBinding); err != nil {
			return nil, err
		}
		gate, err := NewGate(r.Scope, r.Consumer.Owner, s.boot)
		if err != nil {
			return nil, err
		}
		candidate := &activationEntry{store: s, disk: activationRecord{Schema: 1, Scope: r.Scope, Owner: r.Consumer.Owner, Gate: gate.Checkpoint()}, gate: gate, scope: r.Scope, owner: r.Consumer.Owner}
		s.mu.Lock()
		e = s.entries[r.Consumer.Owner.Native]
		if e == nil {
			e = candidate
			s.entries[r.Consumer.Owner.Native] = e
		}
		s.mu.Unlock()
	}
	if e == nil || e.scope != r.Scope || e.owner != r.Consumer.Owner {
		return nil, ErrActivation
	}
	return e, nil
}
func (s *Activations) save(key string, e *activationEntry, d activationRecord, g Gate) error {
	if e.store != nil && e.store != s {
		return e.store.save(key, e, d, g)
	}
	d.Gate = g.Checkpoint()
	raw, err := json.Marshal(d)
	if err == nil {
		err = s.db.Write(map[string][]byte{activationRecordKey(e.owner.Native): raw})
	}
	if err == nil {
		e.disk = d
		e.gate = g
	}
	return err
}
func copyActivation(d activationRecord) activationRecord {
	d.Bindings = append([]activationBinding(nil), d.Bindings...)
	for i := range d.Bindings {
		if d.Bindings[i].Exit != nil {
			exit := *d.Bindings[i].Exit
			d.Bindings[i].Exit = &exit
		}
	}
	return d
}
func bindingIndex(d activationRecord, r Activation) int {
	for i, b := range d.Bindings {
		if b.Ref.Consumer.ID == r.Consumer.ID {
			return i
		}
	}
	return -1
}
func (s *Activations) Plan(ctx context.Context, r Activation) error {
	return s.planAll(ctx, []Activation{r}, false)
}
func (s *Activations) container(ctx context.Context, r Activation, nativeID string) (container.InspectResponse, error) {
	id, err := s.taskIdentity(r)
	if err != nil {
		return container.InspectResponse{}, err
	}
	lookup := nativeID
	if lookup == "" {
		lookup = id.Name
	}
	got, err := s.client.API.ContainerInspect(ctx, lookup, client.ContainerInspectOptions{})
	if err != nil {
		return got.Container, err
	}
	v := got.Container
	if !validNativeID(v.ID) || nativeID != "" && v.ID != nativeID || v.Config == nil || v.State == nil || !id.Matches(v.Name, v.Config.Labels) {
		return v, engine.ErrOwnership
	}
	count := 0
	source, bind, err := s.mountSource(r.NativeKey, r.Scope, r.Consumer.Owner, r.NativeGeneration, r.NativeBinding)
	if err != nil {
		return v, err
	}
	for _, m := range v.Mounts {
		if !bind && m.Type == mount.TypeVolume && m.Name == source || bind && m.Type == mount.TypeBind && m.Source == source {
			if m.RW != r.Consumer.Writable {
				return v, engine.ErrOwnership
			}
			count++
		}
	}
	if count != 1 {
		return v, engine.ErrOwnership
	}
	return v, nil
}

// Activate uses the same whole-task barrier for one or many volumes.
func (s *Activations) Activate(ctx context.Context, r Activation) error {
	return s.ActivateAll(ctx, []Activation{r})
}

func (s *Activations) Retire(ctx context.Context, r Activation) error {
	return s.RetireAll(ctx, []Activation{r})
}

func (s *Activations) returnLease(lease NativeLease) error {
	if owner := s.ownerStore(lease.Owner.Key); owner != nil && owner != s {
		return owner.returnLease(lease)
	}
	if lease.Pin.Token == 0 {
		// Intent is durable before Borrow, so the exact token can be recovered
		// even when its receipt sync failed. No other task owner is substituted.
		r, err := s.native.View(lease.Key)
		if err != nil {
			return err
		}
		pin, ok := r.Consumers[lease.Consumer]
		if !ok {
			return nil
		}
		if pin.Generation != lease.Pin.Generation {
			return reconcile.ErrLease
		}
		lease.Pin = pin
	}
	return s.native.Return(lease)
}

// AbortBeforeCreate consumes the fresh driver's positive fact that Create was
// never called for this original operation. It must never be used by Recover.
func (s *Activations) AbortBeforeCreate(ctx context.Context, r Activation) error {
	s.life.RLock()
	defer s.life.RUnlock()
	e, err := s.entry(r, false)
	if err != nil {
		return err
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	d := copyActivation(e.disk)
	i := bindingIndex(d, r)
	if i < 0 || d.Bindings[i].Ref != r {
		return ErrActivation
	}
	b := d.Bindings[i]
	if !b.Closed {
		if b.NativeID != "" || b.Started || d.Gate.Starting != nil {
			return ErrActivation
		}
		if _, err = s.container(ctx, r, ""); !cerrdefs.IsNotFound(err) {
			return errors.Join(ErrActivation, err)
		}
		d.Bindings[i].Closed = true
		d.Bindings[i].Unsent = true
		d.Bindings[i].CreatePrepared = false
		if err = s.save(r.NativeKey, e, d, e.gate); err != nil {
			return err
		}
	} else if !b.Unsent {
		return ErrActivation
	}
	if !d.Bindings[i].Released {
		if err = s.returnLease(b.Lease); err != nil {
			return err
		}
		d.Bindings[i].Released = true
		return s.save(r.NativeKey, e, d, e.gate)
	}
	return nil
}
func (s *Activations) Fence(r Activation, through uint64) (GateCheckpoint, error) {
	if through < r.Consumer.OwnerRevision {
		return GateCheckpoint{}, ErrActivation
	}
	s.life.RLock()
	defer s.life.RUnlock()
	e, err := s.entry(r, true)
	if err != nil {
		return GateCheckpoint{}, err
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	g, err := e.gate.Fence(through)
	if err != nil {
		return GateCheckpoint{}, err
	}
	if err = s.save(r.NativeKey, e, copyActivation(e.disk), g); err != nil {
		return GateCheckpoint{}, err
	}
	return g.Checkpoint(), nil
}
func (s *Activations) Gone(ctx context.Context, r Activation, private ed25519.PrivateKey) (Gone, error) {
	s.life.RLock()
	defer s.life.RUnlock()
	e, err := s.entry(r, false)
	if err != nil {
		return Gone{}, err
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	i := bindingIndex(e.disk, r)
	if i < 0 {
		return Gone{}, ErrActivation
	}
	b := e.disk.Bindings[i]
	if b.Ref != r || !b.Closed || !b.Released || e.disk.Gate.Starting != nil && *e.disk.Gate.Starting == r.Consumer || len(private) != ed25519.PrivateKeySize || [32]byte(private.Public().(ed25519.PublicKey)) != s.node {
		return Gone{}, ErrActivation
	}
	if b.NativeID != "" {
		if _, err = s.client.API.ContainerInspect(ctx, b.NativeID, client.ContainerInspectOptions{}); !cerrdefs.IsNotFound(err) {
			return Gone{}, errors.Join(ErrActivation, err)
		}
	}
	p := Gone{Scope: r.Scope, Consumer: r.Consumer, Stopped: true, MountsGone: true}
	p.Signature = ed25519.Sign(private, GoneBytes(p))
	return p, nil
}

// ConsumerGone resolves the original local Apply reference after its native
// Task journal has completed Remove. A matching consumer alone is insufficient:
// the scope, Task key and generation must match that retained activation too.
func (s *Activations) ConsumerGone(ctx context.Context, scope Scope, consumer Consumer, taskKey string, generation uint64, private ed25519.PrivateKey) (Gone, error) {
	s.life.RLock()
	if s.closed {
		s.life.RUnlock()
		return Gone{}, ErrActivation
	}
	s.mu.Lock()
	e := s.entries[consumer.Owner.Native]
	s.mu.Unlock()
	if e == nil {
		s.life.RUnlock()
		return Gone{}, ErrActivation
	}
	e.mu.Lock()
	var original Activation
	found := false
	for _, b := range e.disk.Bindings {
		r := b.Ref
		if r.Scope == scope && r.Consumer == consumer && r.TaskKey == taskKey && r.Task.Generation == generation {
			if found {
				e.mu.Unlock()
				s.life.RUnlock()
				return Gone{}, ErrActivation
			}
			original, found = r, true
		}
	}
	e.mu.Unlock()
	s.life.RUnlock()
	if !found {
		return Gone{}, ErrActivation
	}
	return s.Gone(ctx, original, private)
}

// RetainReady proves the original consumers cannot start again: their durable
// activations are Closed/Released, with no uncertain Start or native pin. It
// keeps the owner revision available for a separately authorized new consumer
// generation instead of permanently fencing all future retained-volume use.
func (s *Activations) RetainReady(ctx context.Context, key string, scope Scope, owner Owner) error {
	s.life.RLock()
	defer s.life.RUnlock()
	if s.closed {
		return ErrActivation
	}
	row, err := s.native.View(key)
	if err != nil || row.State.Pending != nil || !row.State.Applied.Present || len(row.Consumers) != 0 {
		return ErrActivation
	}
	var actual Owner
	var actualScope Scope
	if scope.TenantManaged() {
		// Closing original consumers is not a new Start. Current ACL/Drain
		// cannot erase or block their positive terminal observations.
		actual, actualScope, err = s.native.recordedOwner(key, row.State.Applied)
	} else {
		actual, actualScope, err = s.native.Owner(ctx, key)
	}
	if err != nil || actual != owner || actualScope != scope {
		return ErrActivation
	}
	s.mu.Lock()
	e := s.entries[owner.Native]
	s.mu.Unlock()
	if e == nil {
		return nil
	} // Validated owner journal, no activation was installed.
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.disk.Scope != scope || e.disk.Owner != owner || e.disk.Gate.Starting != nil {
		return ErrActivation
	}
	for _, b := range e.disk.Bindings {
		if !b.Closed || !b.Released {
			return ErrActivation
		}
	}
	return nil
}
func (s *Activations) Checkpoint(r Activation) (GateCheckpoint, error) {
	s.life.RLock()
	defer s.life.RUnlock()
	e, err := s.entry(r, false)
	if err != nil {
		return GateCheckpoint{}, err
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.gate.Checkpoint(), nil
}
func (s *Activations) Close() error {
	s.life.Lock()
	defer s.life.Unlock()
	if s.closed {
		return nil
	}
	s.closed = true
	return s.db.Close()
}
