// SPDX-License-Identifier: Apache-2.0

package services

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/jay94ks/seafield/internal/access"
	"github.com/jay94ks/seafield/internal/network"
	"github.com/jay94ks/seafield/internal/reconcile"
	"github.com/jay94ks/seafield/internal/storage"
	"github.com/jay94ks/seafield/internal/tenancy"
	"github.com/jay94ks/seafield/internal/workload"
	"github.com/miekg/dns"
	"golang.org/x/sys/unix"
)

// DNSOwnerPolicy must come from one committed control snapshot. Current is
// called again for admission; a captured configuration is not lasting authority.
type DNSOwnerPolicy struct {
	Unavailable      []DNSAddressReference // current serving filter only; names/allocations remain reserved
	Catalog          access.Catalog
	Networks         tenancy.Networks
	Authority        Authority
	Actor            string
	Config           DNSConfig
	Bridge           string
	BridgeGeneration uint64 // native journal/pin generation; independent of Source.NetworkGeneration
	MaxConnections   int
	ProtectedZones   []string
	RequestTimeout   time.Duration
}

type DNSOwnerOptions struct {
	Cluster                              [32]byte
	Key                                  ed25519.PrivateKey
	Network                              *network.Manager
	Workload                             *workload.Manager
	Workloads                            func() []*workload.Manager
	Roots                                []string
	MaxViews, MaxQueries, MaxConnections int
	IdleTimeout                          time.Duration
	Current                              func(context.Context, string, string) (DNSOwnerPolicy, error)
	// Permit checks the installed member/current quorum immediately before a
	// new native effect. It is not inferred from a read-only policy snapshot.
	Permit func(context.Context, DNSOwnerPolicy) error
}

type dnsBridgeReceipt struct {
	Group     uint64
	Lease     network.BridgeLease
	Namespace [32]byte
	Interface string
	Index     int
	Boot      [32]byte     `json:",omitzero"`
	Original  *NativeScope `json:",omitempty"`
}
type dnsOwnerDisk struct {
	Schema               uint8
	Cluster, Owner, Boot [32]byte
	Stopped              bool
	Settings, DNS        json.RawMessage
	Bridges              []dnsBridgeReceipt
	Roots                []string
	Process              *dnsProcessIdentity `json:",omitempty"`
}

// DNSOwner owns local socket and query I/O. Settings and DNSManager remain the
// ONLY lifecycle algorithms and are synced together before admission/release.
// Close is a process pause: original logical lifetimes/Bridge pins survive it.
type DNSOwner struct {
	effects        sync.Mutex
	mu             sync.Mutex
	options        DNSOwnerOptions
	db             *storage.DB
	settings       Settings
	dns            DNSManager
	bridges        map[uint64]dnsBridgeReceipt
	sockets        map[uint64]*dnsSocketGroup
	boot           [32]byte
	process        dnsProcessIdentity
	ctx            context.Context
	cancel         context.CancelFunc
	closed, failed bool
	lastErr        error
	queryFailures  uint64
	lastQueryError string
	requests       chan struct{}
	connections    chan struct{}
}

func dnsNativeBoot() ([32]byte, error) {
	raw, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if err != nil || len(strings.TrimSpace(string(raw))) != 36 {
		return [32]byte{}, errors.Join(err, ErrLease)
	}
	return sha256.Sum256(append([]byte("sfc-linux-boot-1/"), raw...)), nil
}

func NativeBootID() ([32]byte, error) { return dnsNativeBoot() }
func (o *DNSOwner) clock() Clock {
	var ts unix.Timespec
	err := unix.ClockGettime(unix.CLOCK_MONOTONIC, &ts)
	return dnsEventClock(o.boot, time.Now(), ts, false, err == nil)
}

func dnsEventClock(boot [32]byte, wall time.Time, mono unix.Timespec, hold bool, certain bool) Clock {
	w, m := wall.Unix(), mono.Sec
	if hold {
		if wall.Nanosecond() != 0 {
			w++
		}
		if mono.Nsec != 0 {
			m++
		}
	}
	return Clock{Boot: boot, Wall: w, Mono: m, Certain: certain}
}
func (o *DNSOwner) holdClock() Clock {
	var ts unix.Timespec
	err := unix.ClockGettime(unix.CLOCK_MONOTONIC, &ts)
	return dnsEventClock(o.boot, time.Now(), ts, true, err == nil)
}

func OpenDNSOwner(path string, options DNSOwnerOptions) (*DNSOwner, error) {
	if len(options.Key) != ed25519.PrivateKeySize || options.Network == nil || options.Current == nil || options.Permit == nil || options.MaxConnections < 1 || options.MaxConnections > 4096 || options.IdleTimeout < time.Second || options.IdleTimeout > time.Minute {
		return nil, ErrLease
	}
	boot, err := dnsNativeBoot()
	if err != nil {
		return nil, err
	}
	process, err := currentDNSProcess()
	if err != nil {
		return nil, err
	}
	options.Key = slices.Clone(options.Key)
	options.Roots = slices.Clone(options.Roots)
	owner := [32]byte(options.Key.Public().(ed25519.PublicKey))
	if !slices.Equal(options.Key, ed25519.NewKeyFromSeed(options.Key.Seed())) {
		return nil, ErrLease
	}
	m, err := NewSettings(options.Cluster, owner, boot, options.MaxViews, options.MaxQueries)
	if err != nil {
		return nil, err
	}
	d, err := NewDNSManager(options.Cluster, owner, options.Roots, options.MaxViews, options.MaxQueries)
	if err != nil {
		return nil, err
	}
	options.Roots = slices.Clone(d.protected)
	_, markerErr := os.Lstat(path + ".owner")
	fresh := errors.Is(markerErr, os.ErrNotExist)
	if err = dnsOwnerIdentity(path, options.Cluster, owner); err != nil {
		return nil, err
	}
	db, err := storage.Open(path)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithCancel(context.Background())
	o := &DNSOwner{options: options, db: db, settings: m, dns: d, boot: boot, process: process, ctx: ctx, cancel: cancel, bridges: map[uint64]dnsBridgeReceipt{}, sockets: map[uint64]*dnsSocketGroup{}, requests: make(chan struct{}, options.MaxQueries), connections: make(chan struct{}, options.MaxConnections)}
	raw, err := db.Get("dns-owner")
	if err == nil {
		var disk dnsOwnerDisk
		if json.Unmarshal(raw, &disk) != nil || disk.Schema != 1 || disk.Cluster != options.Cluster || disk.Owner != owner || disk.Boot == ([32]byte{}) {
			err = fmt.Errorf("DNS owner journal identity/boot: %w", ErrLease)
		} else if o.settings, err = DecodeSettings(disk.Settings); err == nil {
			o.dns, err = DecodeDNSManager(disk.DNS)
			if err == nil && (o.settings.cluster != options.Cluster || o.settings.owner != owner || o.settings.boot != disk.Boot || o.settings.maxUsers != options.MaxQueries || o.settings.maxSlots != options.MaxViews || o.dns.cluster != options.Cluster || o.dns.owner != owner || o.dns.maxQueries != options.MaxQueries || o.dns.maxViews != options.MaxViews || !slices.Equal(disk.Roots, options.Roots)) {
				err = ErrLease
			}
			for _, b := range disk.Bridges {
				g, ok := o.settings.groups[b.Group]
				if b.Boot == ([32]byte{}) && b.Original == nil {
					b.Boot = disk.Boot // original schema1 receipt, before rebinding
				}
				if !ok || !validDNSBridgeReceipt(b, g) {
					err = ErrLease
					break
				}
				if _, duplicate := o.bridges[b.Group]; duplicate {
					err = ErrLease
					break
				}
				o.bridges[b.Group] = b
			}
			if err == nil {
				err = o.resumeJournal(disk)
			}
		}
	} else if errors.Is(err, storage.ErrMissing) && fresh {
		err = nil
	}
	if err == nil {
		err = o.save(o.settings, o.dns, false)
	}
	if err != nil {
		cancel()
		_ = db.Close()
		return nil, err
	}
	return o, nil
}

func (o *DNSOwner) save(m Settings, d DNSManager, stopped bool) error {
	s, err := m.Encode()
	if err != nil {
		return err
	}
	raw, err := d.Encode()
	if err != nil {
		return err
	}
	disk := dnsOwnerDisk{Schema: 1, Cluster: o.options.Cluster, Owner: m.owner, Boot: o.boot, Stopped: stopped, Settings: s, DNS: raw, Roots: o.options.Roots, Process: &o.process}
	for _, b := range o.bridges {
		disk.Bridges = append(disk.Bridges, b)
	}
	slices.SortFunc(disk.Bridges, func(a, b dnsBridgeReceipt) int {
		if a.Group < b.Group {
			return -1
		}
		if a.Group > b.Group {
			return 1
		}
		return 0
	})
	value, err := json.Marshal(disk)
	if err != nil {
		return err
	}
	if err = o.db.Write(map[string][]byte{"dns-owner": value}); err != nil {
		o.failed = true
		o.lastErr = err
		return err
	}
	o.settings, o.dns = m, d
	return nil
}

func (o *DNSOwner) proof(step SettingsStep) SettingsProof {
	p := SettingsProof{Cluster: o.settings.cluster, Owner: o.settings.owner, Boot: o.boot, Action: step.Action, Key: step.Key, Group: step.Group, Operation: step.Operation.ID, Kind: step.Operation.Kind, Generation: step.Operation.Target.Generation, Spec: step.Operation.Target.Spec, Outcome: reconcile.EffectApplied, Synced: true, NoPending: true}
	if step.Operation.Kind == reconcile.Remove {
		p.Gone = true
		p.OldAdmissionStopped = step.Action == SettingsActivate
	} else if step.Action == SettingsPrepare {
		p.Inactive = true
	} else {
		p.Serving = true
		p.OldAdmissionStopped = true
	}
	p.Signature = ed25519.Sign(o.options.Key, SettingsProofBytes(p))
	return p
}

// A second private durable identity prevents losing the journal from turning
// an existing Bridge consumer into a fresh owner. Failure leaves the intent;
// recovery must inspect it, never silently reset the DB.
func dnsOwnerIdentity(path string, cluster, owner [32]byte) error {
	if !filepath.IsAbs(path) {
		return ErrLease
	}
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	want := hex.EncodeToString(cluster[:]) + "/" + hex.EncodeToString(owner[:])
	marker := path + ".owner"
	fd, err := unix.Open(marker, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err == nil {
		f := os.NewFile(uintptr(fd), marker)
		defer f.Close()
		info, e := f.Stat()
		if e != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 || info.Size() != int64(len(want)) {
			return errors.Join(e, ErrLease)
		}
		raw := make([]byte, len(want))
		_, e = f.ReadAt(raw, 0)
		if e != nil || string(raw) != want {
			return errors.Join(e, ErrLease)
		}
		_, e = os.Lstat(path)
		return e
	}
	if !errors.Is(err, unix.ENOENT) {
		return err
	}
	if _, e := os.Lstat(path); !errors.Is(e, os.ErrNotExist) {
		return ErrLease
	}
	fd, err = unix.Open(marker, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0600)
	if err != nil {
		return err
	}
	f := os.NewFile(uintptr(fd), marker)
	_, err = f.WriteString(want)
	if err == nil {
		err = f.Sync()
	}
	err = errors.Join(err, f.Close())
	if err != nil {
		return err
	}
	dir, err := os.Open(filepath.Dir(path))
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}

// Apply connects one exact current DNS target. Disabled/serial retirement and
// unclean recovery are deliberately not reported as implemented by this path.
func (o *DNSOwner) Apply(ctx context.Context, tenant, id string) (err error) {
	phase := "current"
	defer func() {
		if err != nil {
			err = fmt.Errorf("DNS apply %s: %w", phase, err)
		}
	}()

	o.effects.Lock()
	defer o.effects.Unlock()
	p, err := o.options.Current(ctx, tenant, id)
	if err != nil {
		return err
	}
	if p.Config.Tenant != tenant || p.Config.ID != id || !p.Config.Enabled || p.Authority.cluster != o.options.Cluster {
		return ErrLease
	}
	if err = o.options.Permit(ctx, p); err != nil {
		return err
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.closed || o.failed {
		return errors.Join(ErrLease, o.lastErr)
	}
	if p.MaxConnections < 1 || p.MaxConnections > o.options.MaxConnections {
		return ErrLease
	}
	phase = "policy"
	protected, err := o.dns.ProtectZones(p.ProtectedZones)
	if err != nil {
		return err
	}
	if err = o.save(o.settings, protected, false); err != nil {
		return err
	}
	local, ok := source(p.Networks, o.options.Cluster, tenant, p.Config.Network, p.Config.Pool)
	if !ok || local.Owner != o.settings.owner {
		return ErrLease
	}
	projection, err := buildDNS(p.Catalog, p.Networks, p.Authority, p.Actor, p.Config)
	if err != nil {
		return errors.Join(err, ErrLease)
	}
	ref, ok := referenceForProjection(p.Authority, projection)
	if !ok {
		return ErrLease
	}
	consumer := "dns/" + hex.EncodeToString(ref.ID[:])
	phase = "bridge"
	lease, err := o.options.Network.Acquire(ctx, p.Bridge, consumer, p.BridgeGeneration)
	if err != nil {
		return err
	}
	matchingPool := false
	for _, pool := range lease.Spec.Pools {
		matchingPool = matchingPool || pool.Prefix == local.Prefix && pool.Gateway == local.Gateway && pool.MTU == local.MTU
	}
	// Authority/referenceForProjection already fences the logical network
	// generation. The actual Bridge lease is fenced by its separate native
	// journal generation, which may originate from a different FSM counter.
	if lease.Key != p.Bridge || lease.Pin.Generation != p.BridgeGeneration || lease.Spec.Network != local.Network || !matchingPool {
		return ErrLease
	}
	binding, err := o.options.Network.ServiceBinding(ctx, lease)
	if err != nil {
		return err
	}
	native := NativeScope{binding.Namespace(), binding.Interface()}
	intent, err := o.dnsSettingsScope(native)
	if err != nil {
		return err
	}
	target, err := DNSSettings(p.Catalog, p.Networks, p.Authority, p.Actor, p.Config, intent)
	if err != nil {
		return err
	}
	phase = "desired"
	m, err := o.settings.Desired(p.Catalog, p.Networks, p.Authority, p.Actor, o.settings.Status(target.key).Desired, target)
	if err != nil {
		return err
	}
	phase = "stage"
	m, slotID, err := m.Stage(p.Catalog, p.Networks, p.Authority, target.key)
	if err != nil {
		return err
	}
	groupID := m.slots[slotID].Group
	receipt, err := o.boundDNSBridge(m.groups[groupID], lease, native, binding.Index())
	if err != nil {
		return err
	}
	o.bridges[groupID] = receipt
	if err = o.save(m, o.dns, false); err != nil {
		return err
	}
	// Persist original preparation, then dispatch, then bind/read-back. An
	// uncertain effect retains that same operation and the durable Bridge pin.
	phase = "native-prepare"
	g := o.settings.groups[groupID]
	stopped := false
	if socket := o.sockets[groupID]; socket != nil {
		socket.mu.Lock()
		stopped = socket.closed
		socket.mu.Unlock()
	}
	if g.State.Pending != nil || !g.State.Applied.Present {
		var op *reconcile.Operation
		if g.State.Pending != nil {
			op = g.State.Pending
		} else {
			m, op, err = o.settings.PlanGroup(groupID)
			if err != nil {
				return err
			}
			if err = o.save(m, o.dns, false); err != nil {
				return err
			}
		}
		if op == nil {
			return ErrLease
		}
		step := SettingsStep{SettingsPrepare, target.key, groupID, *op}
		if step.Operation.Kind != reconcile.Apply {
			return ErrLease
		}
		if step.Operation.Phase == reconcile.Prepared {
			m, err = o.settings.Dispatch(p.Catalog, p.Networks, p.Authority, step)
			if err != nil {
				return err
			}
			if err = o.save(m, o.dns, false); err != nil {
				return err
			}
		}
		if err = o.options.Permit(ctx, p); err != nil {
			return err
		}
		if err = o.prepare(ctx, groupID, binding, local.Gateway, tenant, id); err != nil {
			return err
		}
		m, err = o.settings.Observe(o.proof(step))
		if err != nil {
			return err
		}
		if err = o.save(m, o.dns, false); err != nil {
			return err
		}
	} else if o.sockets[groupID] == nil || stopped {
		if err = o.options.Permit(ctx, p); err != nil {
			return err
		}
		if err = o.prepare(ctx, groupID, binding, local.Gateway, tenant, id); err != nil {
			return err
		}
		if g.Proof == nil {
			return ErrLease
		}
		proof := *g.Proof
		proof.Boot = o.boot
		proof.Signature = ed25519.Sign(o.options.Key, SettingsProofBytes(proof))
		m, err = o.settings.Revalidate(proof)
		if err != nil {
			return err
		}
		if err = o.save(m, o.dns, false); err != nil {
			return err
		}
	}
	phase = "native-switch"
	var op *reconcile.Operation
	if err = o.options.Permit(ctx, p); err != nil {
		return err
	}
	o.sockets[groupID].start()
	scope := o.settings.scopes[target.key]
	if scope.Switch.Pending != nil {
		op = scope.Switch.Pending
	} else {
		m, op, err = o.settings.PlanSwitch(p.Catalog, p.Networks, p.Authority, target.key)
		if err != nil {
			return err
		}
		if err = o.save(m, o.dns, false); err != nil {
			return err
		}
	}
	if op != nil {
		step := SettingsStep{SettingsActivate, target.key, 0, *op}
		if op.Kind != reconcile.Apply {
			return ErrLease
		}
		if op.Phase == reconcile.Prepared {
			m, err = o.settings.Dispatch(p.Catalog, p.Networks, p.Authority, step)
			if err != nil {
				return err
			}
			if err = o.save(m, o.dns, false); err != nil {
				return err
			}
		}
		o.sockets[groupID].start()
		// Admission holds this same mutex, so the old target cannot acquire new
		// users between positive switch evidence and atomic publication below.
		m, err = o.settings.Observe(o.proof(step))
		if err != nil {
			return err
		}
		if err = o.save(m, o.dns, false); err != nil {
			return err
		}
	} else if scope.Proof != nil {
		proof := *scope.Proof
		proof.Boot = o.boot
		proof.Signature = ed25519.Sign(o.options.Key, SettingsProofBytes(proof))
		m, err = o.settings.Revalidate(proof)
		if err != nil {
			return err
		}
		if err = o.save(m, o.dns, false); err != nil {
			return err
		}
	}
	phase = "publish"
	if o.dns.Applied(tenant, id) != p.Config.Source {
		m, d, e := o.settings.PublishDNS(p.Catalog, p.Networks, p.Authority, o.dns, p.Actor, target.key, o.holdClock())
		if e != nil {
			return e
		}
		if err = o.save(m, d, false); err != nil {
			return err
		}
	}
	o.sockets[groupID].start()
	return nil
}

func (o *DNSOwner) origin(ctx context.Context, p DNSOwnerPolicy, b *network.ServiceBinding, peer netip.Addr) (network.Allocation, error) {
	found, known := p.Authority.book.AllocationAt(peer)
	if !known || o.options.Workload == nil {
		return found, ErrLease
	}
	owners := []*workload.Manager{o.options.Workload}
	if o.options.Workloads != nil {
		owners = o.options.Workloads()
	}
	for _, tasks := range owners {
		if tasks == nil {
			continue
		}
		for _, key := range tasks.Keys() {
			if !strings.HasPrefix(found.Endpoint, key+"/") {
				continue
			}
			r, err := tasks.View(key)
			if err != nil || r.State.Pending != nil || r.State.Applied.Generation != found.Generation {
				continue
			}
			s, err := workload.DecodeContainer(r.State.Applied.Spec)
			if err != nil || s.Bridge != b.Lease().Key || s.BridgeGeneration != b.Lease().Pin.Generation || s.IPv4 != peer && s.IPv6 != peer {
				continue
			}
			native, running, err := tasks.NetworkIdentity(ctx, key, found.Generation)
			if err != nil || !running {
				return found, errors.Join(err, ErrLease)
			}
			if err = b.HasEndpoint(ctx, native, peer); err != nil {
				return found, err
			}
			return found, nil
		}
	}
	return found, ErrLease
}

func (o *DNSOwner) query(ctx context.Context, g *dnsSocketGroup, peer netip.Addr, raw []byte, tcp bool) (wire []byte, release func(), failure error) {
	started := time.Now()
	var policyTime, originTime, waitTime, acquireTime, saveTime, answerTime time.Duration
	stage := "policy"
	defer func() {
		if elapsed := time.Since(started); elapsed >= 200*time.Millisecond {
			log.Printf("DNS query slow: elapsed=%s policy=%s origin=%s lock_wait=%s acquire=%s save=%s answer=%s stage=%s failed=%t", elapsed, policyTime, originTime, waitTime, acquireTime, saveTime, answerTime, stage, failure != nil)
		}
		if failure != nil {
			o.queryFailure(stage, failure)
		}
	}()
	p, err := o.options.Current(ctx, g.tenant, g.id)
	policyTime = time.Since(started)
	if err != nil {
		return nil, nil, err
	}
	timeout := p.RequestTimeout
	if timeout == 0 {
		timeout = time.Duration(p.Config.QuerySeconds) * time.Second
	}
	if timeout <= 0 || timeout > time.Duration(p.Config.QuerySeconds)*time.Second {
		return nil, nil, ErrLease
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	stage = "origin"
	at := time.Now()
	a, err := o.origin(ctx, p, g.binding, peer)
	originTime = time.Since(at)
	if err != nil {
		cancel()
		return nil, nil, err
	}
	stage = "admission"
	at = time.Now()
	o.mu.Lock()
	waitTime = time.Since(at)
	at = time.Now()
	if o.closed || o.failed || o.sockets[g.group] != g || o.dns.Applied(g.tenant, g.id) != p.Config.Source {
		o.mu.Unlock()
		cancel()
		return nil, nil, ErrLease
	}
	protected, err := o.dns.ProtectZones(p.ProtectedZones)
	if err != nil {
		o.mu.Unlock()
		cancel()
		return nil, nil, err
	}
	m, d, h, err := o.settings.AcquireDNS(p.Catalog, p.Networks, p.Authority, protected, g.tenant, g.id, a, raw, o.clock())
	acquireTime = time.Since(at)
	if err == nil {
		at = time.Now()
		err = o.save(m, d, false)
		saveTime = time.Since(at)
	}
	if err != nil {
		o.mu.Unlock()
		cancel()
		return nil, nil, err
	}
	at = time.Now()
	result, err := o.dns.Answer(p.Catalog, p.Networks, p.Authority, h.Query, raw, o.clock(), p.Unavailable)
	answerTime = time.Since(at)
	o.mu.Unlock()
	finish := func() {
		started := time.Now()
		defer func() {
			if elapsed := time.Since(started); elapsed >= 200*time.Millisecond {
				log.Printf("DNS query release slow: elapsed=%s", elapsed)
			}
		}()
		defer cancel()
		o.mu.Lock()
		defer o.mu.Unlock()
		proof, e := o.settings.UseFacts(h.Runtime)
		if e == nil {
			proof.Synced = true
			proof.Stopped = true
			proof.NoPending = true
			proof.Signature = ed25519.Sign(o.options.Key, SettingsUseCloseBytes(proof))
			m, d, e = o.settings.ReleaseDNS(o.dns, h, o.holdClock(), proof)
		}
		if e == nil {
			e = o.save(m, d, false)
		}
		if e != nil {
			o.failed = true
			o.lastErr = e
		}
	}
	if err == nil && result.Forward != nil {
		result.Response, err = o.forward(ctx, p, *result.Forward)
	}
	if err != nil {
		o.queryFailure("answer/forward", err)
		request, e := DecodeDNSQuery(raw, 4096)
		if e != nil {
			return nil, finish, e
		}
		response := new(dns.Msg)
		response.SetReply(request)
		response.Rcode = dns.RcodeServerFailure
		result.Response = response
	}
	stage = "encoding"
	wire, err = EncodeDNSReply(raw, result.Response, tcp, p.Config.MaxResponseBytes)
	return wire, finish, err
}

// Query denials are expected for foreign/stale clients and never poison the
// owner or discard a durable query. Keep a bounded node-local diagnostic,
// without request names/bytes, so an admission failure is not a silent timeout.
func (o *DNSOwner) queryFailure(stage string, err error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.queryFailures != ^uint64(0) {
		o.queryFailures++
	}
	message := err.Error()
	if len(message) > 256 {
		message = message[:256]
	}
	o.lastQueryError = stage + ": " + message
}

func (o *DNSOwner) forward(ctx context.Context, p DNSOwnerPolicy, plan DNSForward) (*dns.Msg, error) {
	var last error
	for _, peer := range plan.Upstreams() {
		exchange, err := plan.Exchange(peer, dns.Id())
		if err != nil {
			return nil, err
		}
		request, err := exchange.Request()
		if err != nil {
			return nil, err
		}
		for _, tcp := range []bool{false, true} {
			response, err := exchangeDNSUpstream(ctx, peer, request, tcp, plan.maxBytes)
			if err != nil {
				last = err
				break
			}
			if response.Truncated && !tcp {
				continue
			}
			raw, err := response.Pack()
			if err != nil {
				return nil, err
			}
			current, err := o.options.Current(ctx, p.Config.Tenant, p.Config.ID)
			if err != nil {
				return nil, err
			}
			o.mu.Lock()
			protected, e := o.dns.ProtectZones(current.ProtectedZones)
			if e != nil {
				o.mu.Unlock()
				return nil, e
			}
			d, result, err := protected.CompleteForward(current.Catalog, current.Networks, current.Authority, exchange, peer, raw, o.clock())
			err = errors.Join(err, o.save(o.settings, d, false))
			o.mu.Unlock()
			return result, err
		}
	}
	return nil, errors.Join(ErrProtocol, last)
}

type DNSOwnerStatus struct {
	Settings        SettingsStatus
	Views           []DNSViewStatus
	Queries         int
	Sockets         int
	Stopped, Failed bool
	Ready           bool
	QueryFailures   uint64 `json:",omitempty"`
	LastQueryError  string `json:",omitempty"`
}

func (o *DNSOwner) Status(tenant, id string) DNSOwnerStatus {
	o.mu.Lock()
	defer o.mu.Unlock()
	key := "dns/" + dnsKey(tenant, id)
	ready := false
	if slot, ok := o.settings.slots[o.settings.scopes[key].Current]; ok {
		if g := o.sockets[slot.Group]; g != nil {
			g.mu.Lock()
			ready = g.started && !g.closed && !o.closed && !o.failed
			g.mu.Unlock()
		}
	}
	views := o.dns.Views()
	queries := 0
	views = slices.DeleteFunc(views, func(view DNSViewStatus) bool {
		if view.Tenant != tenant || view.Service != id {
			return true
		}
		queries += view.Queries
		return false
	})
	sockets := 0
	for _, group := range o.sockets {
		if group.tenant == tenant && group.id == id {
			sockets++
		}
	}
	return DNSOwnerStatus{Settings: o.settings.Status(key), Views: views, Queries: queries, Sockets: sockets, Stopped: o.closed, Failed: o.failed, Ready: ready, QueryFailures: o.queryFailures, LastQueryError: o.lastQueryError}
}

// Inspect proves the current original Bridge/interface still exists. Stored
// Applied or an open but orphaned FD alone is not a fresh native observation.
func (o *DNSOwner) Inspect(ctx context.Context, tenant, id string) (DNSOwnerStatus, error) {
	status := o.Status(tenant, id)
	if !status.Ready {
		return status, ErrLease
	}
	o.mu.Lock()
	slot := o.settings.slots[o.settings.scopes["dns/"+dnsKey(tenant, id)].Current]
	g := o.sockets[slot.Group]
	o.mu.Unlock()
	if g == nil {
		return status, ErrLease
	}
	if err := g.binding.Check(ctx); err != nil {
		return status, err
	}
	return o.Status(tenant, id), nil
}

func (o *DNSOwner) Close() error {
	o.effects.Lock()
	defer o.effects.Unlock()
	o.mu.Lock()
	if o.closed {
		err := o.lastErr
		o.mu.Unlock()
		return err
	}
	o.closed = true
	o.cancel()
	groups := make([]*dnsSocketGroup, 0, len(o.sockets))
	for _, g := range o.sockets {
		groups = append(groups, g)
	}
	o.mu.Unlock()
	var err error
	for _, g := range groups {
		err = errors.Join(err, g.close())
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	if len(o.dns.Queries()) != 0 || o.failed {
		err = errors.Join(err, ErrLease, o.lastErr)
	}
	if err == nil {
		err = o.save(o.settings, o.dns, true)
	}
	o.lastErr = errors.Join(err, o.db.Close())
	return o.lastErr
}
