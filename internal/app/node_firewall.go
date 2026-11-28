// SPDX-License-Identifier: Apache-2.0

package app

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"path/filepath"
	"sort"
	"strconv"
	"sync"
	"time"

	"github.com/jay94ks/seafield/internal/access"
	"github.com/jay94ks/seafield/internal/cluster"
	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/config"
	"github.com/jay94ks/seafield/internal/eventlog"
	"github.com/jay94ks/seafield/internal/firewall"
	"github.com/jay94ks/seafield/internal/identity"
	"github.com/jay94ks/seafield/internal/schema"
	"github.com/jay94ks/seafield/internal/sfcp"
	"github.com/jay94ks/seafield/internal/storage"
)

// nodeFirewallRuntime is this server's own firewall chain
// (devel/proposals/node-firewall.md). Its rules live in
// <state_dir>/firewall/firewall.db, never in Raft: a change is applied to
// SFC-INPUT at once and then saved. When node.yaml does not set
// firewall.managed, db is nil and iptables is left alone apart from taking
// out an SFC-INPUT left from an earlier start.
type nodeFirewallRuntime struct {
	mu       sync.Mutex
	db       *storage.DB
	host     firewall.Host
	node     string
	keep     []config.KeepOpenPort
	sfcpPort uint16
	ingress  func() []firewall.Port
	// cluster is the committed cluster firewall, saved as "cluster" so a
	// restart applies it before Raft catches up.
	cluster firewall.State
	// applyErr is why SFC-INPUT does not hold the saved rules (reconcile
	// keeps trying); warned the last one logged.
	applyErr, warned string
}

type nodeFirewallJournal struct {
	Request [32]byte
	Result  control.NodeFirewallResult
}

const nodeFirewallOpKeep = 256

func (r *Runtime) openNodeFirewall(ctx context.Context, stateRoot, node, listen string, f config.NodeFirewall) error {
	if r.historicalOwner {
		return nil
	}
	fw := &nodeFirewallRuntime{host: firewall.Real, node: node}
	fw.ingress = func() []firewall.Port {
		if r.ingress == nil {
			return nil
		}
		out := []firewall.Port{}
		for _, e := range r.ingress.ListenEndpoints() {
			out = append(out, firewall.Port{Proto: e.Proto, Port: e.Port, Reason: "ingress"})
		}
		return out
	}
	r.nodeFirewall = fw
	if !f.Managed {
		// Not ours to control: only take out a chain an earlier start made.
		if err := firewall.Remove(ctx, fw.host); err != nil {
			log.Printf("node firewall: not managed; could not remove an old %s chain: %v", firewall.Chain, err)
		}
		return nil
	}
	keep, err := f.KeepOpenPorts()
	if err != nil {
		return err
	}
	_, port, err := net.SplitHostPort(listen)
	n, perr := strconv.ParseUint(port, 10, 16)
	if err != nil || perr != nil {
		return fmt.Errorf("node firewall: node.listen %q has no port", listen)
	}
	fw.keep, fw.sfcpPort = keep, uint16(n)
	if fw.db, err = storage.Open(filepath.Join(stateRoot, "firewall", "firewall.db")); err != nil {
		return err
	}
	s, err := fw.state()
	if err == nil {
		fw.cluster, err = fw.clusterCopy()
	}
	if err != nil {
		fw.db.Close()
		return err
	}
	// The saved rules go back in before anything else listens, so a restart
	// never leaves the server open.
	fw.mu.Lock()
	fw.ensure(ctx, fw.layers(s))
	fw.mu.Unlock()
	return nil
}

func (f *nodeFirewallRuntime) layers(s firewall.State) firewall.Layers {
	return firewall.Layers{Node: s, Cluster: f.cluster}
}

// clusterCopy is the cluster firewall this server last applied.
func (f *nodeFirewallRuntime) clusterCopy() (firewall.State, error) {
	raw, err := f.db.Get("cluster")
	if errors.Is(err, storage.ErrMissing) {
		return firewall.NewCluster(), nil
	}
	if err != nil {
		return firewall.State{}, err
	}
	s, err := schema.Decode[firewall.State](raw)
	if err != nil || s.Scope != firewall.ScopeCluster || !s.Valid() {
		return firewall.State{}, errors.New("node firewall: saved cluster rules are not valid")
	}
	return s, nil
}

func (f *nodeFirewallRuntime) state() (firewall.State, error) {
	raw, err := f.db.Get("state")
	if errors.Is(err, storage.ErrMissing) {
		return firewall.New(), nil
	}
	if err != nil {
		return firewall.State{}, err
	}
	s, err := schema.Decode[firewall.State](raw)
	if err != nil || s.Scope != "" || !s.Valid() {
		return firewall.State{}, errors.New("node firewall: saved rules are not valid")
	}
	return s, nil
}

func (f *nodeFirewallRuntime) locks() firewall.Locks {
	l := firewall.Locks{Ports: []firewall.Port{{Proto: "udp", Port: f.sfcpPort, Reason: "sfcp"}}}
	for _, k := range f.keep {
		l.Ports = append(l.Ports, firewall.Port{Proto: k.Proto, Port: k.Port, From: k.From, Reason: "keep-open"})
	}
	if f.ingress != nil {
		l.Ports = append(l.Ports, f.ingress()...)
	}
	return l
}

// ensure puts s into SFC-INPUT unless it is already there; f.mu is held.
func (f *nodeFirewallRuntime) ensure(ctx context.Context, s firewall.Layers) {
	l := f.locks()
	ok := true
	for _, family := range firewall.Families {
		in, err := firewall.Installed(ctx, f.host, family, firewall.Lines(family, s, l))
		ok = ok && err == nil && in
	}
	if ok {
		f.setApplyErr("")
		return
	}
	if err := firewall.Apply(ctx, f.host, s, l); err != nil {
		f.setApplyErr(err.Error())
		return
	}
	f.setApplyErr("")
}

func (f *nodeFirewallRuntime) setApplyErr(e string) {
	if len(e) > 512 {
		e = e[:512]
	}
	f.applyErr = e
	if e != f.warned {
		f.warned = e
		if e == "" {
			log.Printf("node firewall: %s holds the saved rules", firewall.Chain)
		} else {
			log.Printf("node firewall: could not apply the saved rules: %s", e)
		}
	}
}

// reconcileNodeFirewall follows the committed cluster firewall, puts the
// rules back when someone flushed the chain or moved the jump, and follows
// ingress listeners as they come and go.
func (r *Runtime) reconcileNodeFirewall(ctx context.Context, v cluster.View) error {
	f := r.nodeFirewall
	if f == nil || f.db == nil || !f.mu.TryLock() {
		return nil
	}
	defer f.mu.Unlock()
	s, err := f.state()
	if err != nil {
		return err
	}
	if c, err := r.controlPolicy.ClusterFirewall(v.State); err != nil {
		log.Printf("node firewall: could not read the cluster firewall; keeping revision %d: %v", f.cluster.Revision, err)
	} else if c.Revision > f.cluster.Revision {
		raw, _ := json.Marshal(c)
		if err := f.db.Write(map[string][]byte{"cluster": raw}); err != nil {
			return err
		}
		f.cluster = c
	}
	f.ensure(ctx, f.layers(s))
	return nil
}

func (f *nodeFirewallRuntime) Close() error {
	if f == nil || f.db == nil {
		return nil
	}
	return f.db.Close()
}

// nodeFirewallRequest serves a user's firewall request on the server that
// holds the session's connection: it runs here or is relayed to the owner
// over SFCP, never through Raft.
func (r *Runtime) nodeFirewallRequest(ctx context.Context, read control.NodeFirewallRead) (control.NodeFirewallResult, error) {
	if read.Owner == r.Identity.Public {
		return r.nodeFirewallLocal(ctx, read)
	}
	peer, ok := r.Mesh.Peer(sfcp.Identity(read.Owner))
	if !ok || !peer.Member || peer.ID != read.Op.Node {
		return control.NodeFirewallResult{}, sfcp.ErrAdmission
	}
	raw, _ := json.Marshal(read)
	reply, err := cluster.CallManagement(ctx, r.Mesh, r.Identity, r.controlPolicy.Cluster, peer, cluster.ManagementRequest{Method: "node-firewall-owner", Input: raw})
	if err != nil {
		return control.NodeFirewallResult{}, err
	}
	result, err := schema.Decode[control.NodeFirewallResult](reply.Data)
	if err != nil || !result.Valid() || result.Node != read.Op.Node || result.Action != read.Op.Action {
		return control.NodeFirewallResult{}, sfcp.ErrAdmission
	}
	return result, nil
}

func (r *Runtime) nodeFirewallLocal(ctx context.Context, read control.NodeFirewallRead) (control.NodeFirewallResult, error) {
	f := r.nodeFirewall
	if r.installation == nil || f == nil || read.Owner != r.Identity.Public || read.Op.Node != r.installation.record.Root.Self.ID {
		return control.NodeFirewallResult{}, sfcp.ErrAdmission
	}
	// The session is checked again on the owner at a quorum read, as for
	// disks; an earlier approval is not a lasting grant.
	raw, _ := json.Marshal(read)
	permit, err := r.appCall(ctx, "node-firewall-permit", raw)
	if err != nil {
		return control.NodeFirewallResult{}, err
	}
	current, err := schema.Decode[control.NodeFirewallRead](permit.Data)
	if err != nil || !sameFirewallOp(current.Op, read.Op) || current.Owner != r.Identity.Public || !bytes.Equal(access.SessionBytes(current.Session), access.SessionBytes(read.Session)) || !bytes.Equal(current.Session.Signature, read.Session.Signature) {
		return control.NodeFirewallResult{}, sfcp.ErrAdmission
	}
	view, err := r.Engine().ReadAtLeast(ctx, current.Index)
	if err != nil {
		return control.NodeFirewallResult{}, err
	}
	live, err := r.controlPolicy.ReadNodeFirewall(view.State, current.Session, time.Now().Unix(), current.Op)
	if err != nil || view.State.Index() < current.Index || view.State.ModuleEpoch() != current.Epoch || live.Owner != current.Owner || live.MembersRoot != current.MembersRoot {
		return control.NodeFirewallResult{}, sfcp.ErrAdmission
	}
	return f.serve(ctx, current, r.recordNodeFirewallEvent), nil
}

func sameFirewallOp(a, b control.NodeFirewallOp) bool {
	ra, _ := json.Marshal(a)
	rb, _ := json.Marshal(b)
	return bytes.Equal(ra, rb)
}

// serve answers one checked request.
func (f *nodeFirewallRuntime) serve(ctx context.Context, read control.NodeFirewallRead, record func(control.NodeFirewallResult, string)) control.NodeFirewallResult {
	op := read.Op
	base := control.NodeFirewallResult{Schema: 1, Node: op.Node, Action: op.Action}
	if f.db == nil {
		if op.Action == "change" {
			base.Code, base.Error = "not-managed", "node.yaml firewall.managed is off on "+op.Node
		}
		base.View = &control.NodeFirewallView{Schema: 1, Node: op.Node}
		return base
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	switch op.Action {
	case "show":
		s, err := f.state()
		if err != nil {
			base.Code, base.Error = "apply-failed", err.Error()
			return base
		}
		base.View = f.view(ctx, s)
		return base
	case "log":
		return f.log(base, op.After)
	}
	raw, _ := json.Marshal(op)
	request := sha256.Sum256(append([]byte("sfc-node-firewall-op-1\x00"), raw...))
	if old, err := f.db.Get("op/" + op.Operation); err == nil {
		j, e := schema.Decode[nodeFirewallJournal](old)
		if e == nil && j.Request == request {
			return j.Result // the original outcome; never applied twice
		}
		base.Code, base.Error = "operation-conflict", "this operation ID was used for another change"
		return base
	} else if !errors.Is(err, storage.ErrMissing) {
		base.Code, base.Error = "apply-failed", err.Error()
		return base
	}
	s, err := f.state()
	if err != nil {
		base.Code, base.Error = "apply-failed", err.Error()
		return base
	}
	next, added, err := s.Change(op.Revision, *op.Delta)
	if err != nil {
		base.Code, base.Error = firewall.Code(err), err.Error()
		base.View = f.view(ctx, s)
		return base
	}
	previous := f.layers(s)
	if err := firewall.Apply(ctx, f.host, f.layers(next), f.locks()); err != nil {
		base.Code, base.Error = "apply-failed", bounded(err.Error())
		base.View = f.view(ctx, s)
		record(base, read.Session.User)
		return base
	}
	change := control.NodeFirewallChange{Operation: op.Operation, User: read.Session.User, At: time.Now().Unix(), From: s.Revision, To: next.Revision, Delta: *op.Delta, Added: added}
	base.Change = &change
	stateRaw, _ := json.Marshal(next)
	changeRaw, _ := json.Marshal(change)
	writes := map[string][]byte{"state": stateRaw, logKey(next.Revision): changeRaw}
	if next.Revision > control.NodeFirewallLogKeep {
		writes[logKey(next.Revision-control.NodeFirewallLogKeep)] = nil
	}
	f.trimOps(writes)
	j, _ := json.Marshal(nodeFirewallJournal{Request: request, Result: base})
	writes["op/"+op.Operation] = j
	if err := f.db.Write(writes); err != nil {
		// Applied but not saved: the kernel holds next until reconcile puts
		// the saved rules back; a retry with the same ID applies it again.
		log.Printf("node firewall: applied revision %d but could not save it: %v", next.Revision, err)
		base.Change, base.Code, base.Error = nil, "apply-failed", "could not save the rules: "+bounded(err.Error())
		f.ensure(ctx, previous)
		base.View = f.view(ctx, s)
		return base
	}
	f.setApplyErr("")
	base.View = f.view(ctx, next)
	record(base, read.Session.User)
	return base
}

func bounded(s string) string {
	if len(s) > 512 {
		return s[:512]
	}
	return s
}

func logKey(revision uint64) string { return fmt.Sprintf("log/%020d", revision) }

// trimOps drops the oldest operation rows beyond nodeFirewallOpKeep.
func (f *nodeFirewallRuntime) trimOps(writes map[string][]byte) {
	rows, err := f.db.Scan("op/")
	if err != nil || len(rows) < nodeFirewallOpKeep {
		return
	}
	type row struct {
		key string
		at  int64
	}
	all := []row{}
	for k, raw := range rows {
		j, _ := schema.Decode[nodeFirewallJournal](raw)
		at := int64(0)
		if j.Result.Change != nil {
			at = j.Result.Change.At
		}
		all = append(all, row{k, at})
	}
	sort.Slice(all, func(i, j int) bool { return all[i].at < all[j].at || all[i].at == all[j].at && all[i].key < all[j].key })
	for _, x := range all[:len(all)-nodeFirewallOpKeep+1] {
		writes[x.key] = nil
	}
}

func (f *nodeFirewallRuntime) view(ctx context.Context, s firewall.State) *control.NodeFirewallView {
	l := f.locks()
	ls := f.layers(s)
	c := f.cluster
	v := &control.NodeFirewallView{Schema: 1, Node: f.node, Managed: true, Revision: s.Revision, Policy: s.Policy, Rules: s.Rules, MaxRules: firewall.MaxRules, Cluster: &c, Effective: firewall.Effective(s, c), Shadowed: firewall.Shadowed(ls), Locked: l.List(), ApplyError: f.applyErr}
	applied := true
	lines, truncated, err := firewall.Operator(ctx, f.host)
	if err != nil && v.ApplyError == "" {
		v.ApplyError = bounded(err.Error())
	}
	v.Operator, v.OperatorFormat, v.OperatorTruncated = lines, "nft", truncated
	for _, family := range firewall.Families {
		in, err := firewall.Installed(ctx, f.host, family, firewall.Lines(family, ls, l))
		applied = applied && err == nil && in
	}
	v.Applied = applied
	return v
}

// log is up to 50 changes, newest first, before revision after.
func (f *nodeFirewallRuntime) log(base control.NodeFirewallResult, after uint64) control.NodeFirewallResult {
	rows, err := f.db.Scan("log/")
	if err != nil {
		base.Code, base.Error = "apply-failed", err.Error()
		return base
	}
	keys := make([]string, 0, len(rows))
	for k := range rows {
		keys = append(keys, k)
	}
	sort.Sort(sort.Reverse(sort.StringSlice(keys)))
	for _, k := range keys {
		c, err := schema.Decode[control.NodeFirewallChange](rows[k])
		if err != nil || after != 0 && c.To >= after {
			continue
		}
		if len(base.Log) == 50 {
			base.More = true
			break
		}
		base.Log = append(base.Log, c)
	}
	return base
}

// recordNodeFirewallEvent leaves who changed this server's firewall in the
// signed event log every server keeps.
func (r *Runtime) recordNodeFirewallEvent(result control.NodeFirewallResult, user string) {
	if r.events == nil {
		return
	}
	kind := "node-firewall-changed"
	if result.Code != "" {
		kind = "node-firewall-failed"
	}
	if len(user) > 63 {
		user = user[:63]
	}
	now := uint64(time.Now().UnixMilli())
	d := eventlog.Detail{Actor: user, Code: result.Code}
	operation := "unknown"
	if c := result.Change; c != nil {
		operation, d.Operation, d.FromVersion, d.ToVersion, d.Reason = c.Operation, c.Operation, c.From, c.To, firewall.Summary(c.Delta, c.Added)
	}
	e := eventlog.Event{Kind: kind, Scope: "node", At: now, Target: eventlog.Target{Node: result.Node}, Detail: d}
	if _, err := r.events.Append("node-firewall/"+operation+"/"+strconv.FormatUint(now, 10), e, now); err != nil {
		log.Printf("node firewall event: error=%v", err)
	}
}

// nodeReadNodeFirewall is node-firewall-permit (leader) and
// node-firewall-owner (the server whose firewall it is).
func (r *Runtime) nodeReadNodeFirewall(ctx context.Context, method, key string, input []byte, v cluster.View) (json.RawMessage, error) {
	caller, err := identity.ParseKey(key)
	q, decodeErr := schema.Decode[control.NodeFirewallRead](input)
	d, memberErr := r.controlPolicy.Members(v.State)
	if err != nil || decodeErr != nil || memberErr != nil || !d.MemberKey(caller) {
		return nil, sfcp.ErrAdmission
	}
	if method == "node-firewall-owner" {
		result, err := r.nodeFirewallLocal(ctx, q)
		if err != nil {
			return nil, err
		}
		return json.Marshal(result)
	}
	read, err := r.controlPolicy.ReadNodeFirewall(v.State, q.Session, time.Now().Unix(), q.Op)
	if err != nil || v.Local || read.Owner != caller {
		return nil, sfcp.ErrAdmission
	}
	return json.Marshal(read)
}
