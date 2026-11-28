// SPDX-License-Identifier: Apache-2.0

package sfc

import (
	"context"
	"errors"

	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/firewall"
)

// fakeFirewall is one fake server's firewall: rules, log and the original
// results by operation ID.
type fakeFirewall struct {
	unmanaged bool
	state     firewall.State
	log       []control.NodeFirewallChange
	ops       map[string]control.NodeFirewallResult
	cluster   *firewall.State // the cluster firewall, set before each view
}

func (w *world) firewall(node string) *fakeFirewall {
	if w.firewalls == nil {
		w.firewalls = map[string]*fakeFirewall{}
	}
	f := w.firewalls[node]
	if f == nil {
		f = &fakeFirewall{state: firewall.New(), ops: map[string]control.NodeFirewallResult{}}
		w.firewalls[node] = f
	}
	return f
}

// SetFirewallManaged turns a fake server's node.yaml firewall.managed on or
// off (every fake server starts managed).
func (f *Fake) SetFirewallManaged(node string, managed bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.w.firewall(node).unmanaged = !managed
}

func (f *fakeFirewall) view(node string) *control.NodeFirewallView {
	if f.unmanaged {
		return &control.NodeFirewallView{Schema: 1, Node: node}
	}
	locks := firewall.Locks{Ports: []firewall.Port{{Proto: "udp", Port: 7443, Reason: "sfcp"}, {Proto: "tcp", Port: 22, Reason: "keep-open"}, {Proto: "tcp", Port: 443, Reason: "ingress"}}}
	cluster := firewall.NewCluster()
	if f.cluster != nil {
		cluster = *f.cluster
	}
	ls := firewall.Layers{Node: f.state, Cluster: cluster}
	return &control.NodeFirewallView{Schema: 1, Node: node, Managed: true, Revision: f.state.Revision, Policy: f.state.Policy, Rules: append([]firewall.Rule{}, f.state.Rules...), MaxRules: firewall.MaxRules, Locked: locks.List(),
		Cluster: &cluster, Effective: firewall.Effective(f.state, cluster), Shadowed: firewall.Shadowed(ls),
		Operator: []string{"ip filter INPUT (hook input, priority 0, policy accept)", "  ip protocol tcp tcp dport 8080 counter drop", "ip6 filter INPUT (hook input, priority 0, policy accept)"}, OperatorFormat: "nft", Applied: true}
}

// NodeFirewall: the fake applies changes like a server (revision + delta,
// same codes) without touching iptables.
func (c *fakeConn) NodeFirewall(ctx context.Context, op control.NodeFirewallOp) (control.NodeFirewallResult, error) {
	const m = "node-firewall"
	if !op.Valid() {
		return control.NodeFirewallResult{}, fail(m, CodeInvalid, "")
	}
	if err := c.adminRead(ctx, m, op.Node); err != nil {
		return control.NodeFirewallResult{}, err
	}
	defer c.unlock()
	f := c.f.w.firewall(op.Node)
	f.cluster = c.f.w.clusterFW
	r := control.NodeFirewallResult{Schema: 1, Node: op.Node, Action: op.Action}
	if f.unmanaged {
		r.View = f.view(op.Node)
		if op.Action == "change" {
			r.Code, r.Error = "not-managed", "node.yaml firewall.managed is off on "+op.Node
		}
		return r, nil
	}
	switch op.Action {
	case "show":
		r.View = f.view(op.Node)
		return r, nil
	case "log":
		for i := len(f.log) - 1; i >= 0; i-- {
			if op.After != 0 && f.log[i].To >= op.After {
				continue
			}
			if len(r.Log) == 50 {
				r.More = true
				break
			}
			r.Log = append(r.Log, f.log[i])
		}
		return r, nil
	}
	if old, ok := f.ops[op.Operation]; ok {
		return old, nil
	}
	next, added, err := f.state.Change(op.Revision, *op.Delta)
	if err != nil {
		r.Code, r.Error, r.View = firewall.Code(err), err.Error(), f.view(op.Node)
		return r, nil
	}
	change := control.NodeFirewallChange{Operation: op.Operation, User: "admin", At: c.f.now().Unix(), From: f.state.Revision, To: next.Revision, Delta: *op.Delta, Added: added}
	f.state = next
	f.log = append(f.log, change)
	r.Change, r.View = &change, f.view(op.Node)
	f.ops[op.Operation] = r
	return r, nil
}

// ClusterFirewall: the committed cluster firewall (system admin).
func (c *fakeConn) ClusterFirewall(ctx context.Context) (control.ClusterFirewallView, error) {
	const m = "cluster-firewall"
	user, err := c.lockSession(ctx, m)
	if err != nil {
		return control.ClusterFirewallView{}, err
	}
	defer c.unlock()
	if !c.f.w.admin(user) {
		return control.ClusterFirewallView{}, fail(m, CodeDenied, "")
	}
	return control.ClusterFirewallView{Schema: 1, Firewall: c.f.w.clusterFirewall(), MaxRules: firewall.MaxRules}, nil
}

func (w *world) clusterFirewall() firewall.State {
	if w.clusterFW == nil {
		return firewall.NewCluster()
	}
	return *w.clusterFW
}

// applyClusterFirewall models the set-cluster-firewall reducer.
func (c *fakeConn) applyClusterFirewall(op UserOperation, actor string) error {
	w := c.f.w
	if !w.admin(actor) {
		return errForbidden
	}
	var d firewall.Delta
	if decodePayload(op.Change.Payload, &d) != nil || d.Empty() {
		return errors.New("payload")
	}
	next, _, err := w.clusterFirewall().Change(op.Change.Expected, d)
	if err != nil {
		return errCAS
	}
	w.clusterFW = &next
	return nil
}
