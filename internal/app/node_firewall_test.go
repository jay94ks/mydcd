// SPDX-License-Identifier: Apache-2.0

package app

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jay94ks/seafield/internal/cluster"
	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/firewall"
	"github.com/jay94ks/seafield/internal/storage"
)

// recordingHost keeps SFC-INPUT per family as iptables lines and its
// marker; fail makes writes fail without changing anything.
type recordingHost struct {
	chain  map[int][]string
	marker map[int]string
	fail   bool
}

func (h *recordingHost) State(_ context.Context, family int) (firewall.ChainState, error) {
	lines, ok := h.chain[family]
	if !ok {
		return firewall.ChainState{}, nil
	}
	return firewall.ChainState{Exists: true, Marker: h.marker[family], Count: len(lines), Jumps: 1, First: true}, nil
}

func (h *recordingHost) Write(_ context.Context, plan map[int][]firewall.Line) error {
	if h.fail {
		return errors.New("nftables: boom")
	}
	if h.chain == nil {
		h.chain, h.marker = map[int][]string{}, map[int]string{}
	}
	for family, lines := range plan {
		if lines == nil {
			delete(h.chain, family)
			continue
		}
		out := []string{}
		for _, l := range lines {
			out = append(out, l.String())
		}
		h.chain[family] = out
		if len(lines) > 0 {
			h.marker[family] = lines[0].Comment
		}
	}
	return nil
}

func (h *recordingHost) Operator(context.Context) ([]string, bool, error) { return nil, false, nil }

func TestNodeFirewallServe(t *testing.T) {
	db, err := storage.Open(filepath.Join(t.TempDir(), "firewall.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	host := &recordingHost{}
	f := &nodeFirewallRuntime{db: db, host: host, node: "vps1", sfcpPort: 7443}
	ctx := context.Background()
	events := []control.NodeFirewallResult{}
	record := func(r control.NodeFirewallResult, _ string) { events = append(events, r) }
	change := func(id string, revision uint64, d firewall.Delta) control.NodeFirewallResult {
		return f.serve(ctx, control.NodeFirewallRead{Op: control.NodeFirewallOp{Operation: id, Node: "vps1", Action: "change", Revision: revision, Delta: &d}}, record)
	}
	add := firewall.Delta{Add: []firewall.Rule{{Action: "allow", Proto: "tcp", Ports: "443"}}}
	r := change("fw-1", 0, add)
	if r.Code != "" || r.Change == nil || r.Change.To != 1 || !r.View.Applied || len(host.chain[4]) == 0 || len(events) != 1 {
		t.Fatal(r, host.chain)
	}
	if again := change("fw-1", 0, add); again.Change == nil || again.Change.To != 1 || len(events) != 1 {
		t.Fatal("replay must return the first result without applying again", again)
	}
	if other := change("fw-1", 0, firewall.Delta{Policy: "drop"}); other.Code != "operation-conflict" {
		t.Fatal(other)
	}
	if stale := change("fw-2", 0, firewall.Delta{Policy: "drop"}); stale.Code != "revision" || stale.View.Revision != 1 {
		t.Fatal(stale)
	}
	host.fail = true
	before := append([]string{}, host.chain[4]...)
	if failed := change("fw-3", 1, firewall.Delta{Policy: "drop"}); failed.Code != "apply-failed" || failed.View.Revision != 1 || len(events) != 2 || events[1].Code != "apply-failed" {
		t.Fatal(failed)
	}
	host.fail = false
	if strings.Join(host.chain[4], "\n") != strings.Join(before, "\n") {
		t.Fatal("a failed apply changed the chain")
	}
	if ok := change("fw-4", 1, firewall.Delta{Delete: []string{"r1"}, Policy: "drop"}); ok.Code != "" || ok.View.Policy != "drop" || len(ok.View.Rules) != 0 {
		t.Fatal(ok)
	}
	log := f.serve(ctx, control.NodeFirewallRead{Op: control.NodeFirewallOp{Node: "vps1", Action: "log"}}, record)
	if len(log.Log) != 2 || log.Log[0].To != 2 || log.Log[1].To != 1 {
		t.Fatal(log)
	}
	if older := f.serve(ctx, control.NodeFirewallRead{Op: control.NodeFirewallOp{Node: "vps1", Action: "log", After: 2}}, record); len(older.Log) != 1 || older.Log[0].To != 1 {
		t.Fatal(older)
	}
	// Someone flushed the chain: reconcile puts the saved rules back.
	host.chain = nil
	r2 := &Runtime{nodeFirewall: f}
	if err := r2.reconcileNodeFirewall(ctx, cluster.View{}); err != nil || len(host.chain[4]) == 0 {
		t.Fatal(err, host.chain)
	}
	unmanaged := (&nodeFirewallRuntime{node: "jay2"}).serve(ctx, control.NodeFirewallRead{Op: control.NodeFirewallOp{Operation: "x", Node: "jay2", Action: "change", Delta: &add}}, record)
	if unmanaged.Code != "not-managed" || unmanaged.View == nil || unmanaged.View.Managed {
		t.Fatal(unmanaged)
	}
}

func TestDeltaSummary(t *testing.T) {
	s := firewall.Summary(firewall.Delta{Add: []firewall.Rule{{Action: "allow", Proto: "tcp", Ports: "443", From: []string{"10.0.0.0/8"}}}, Delete: []string{"r2"}, Policy: "drop"}, []string{"r5"})
	if s != "add r5 allow tcp 443 from 10.0.0.0/8; delete r2; policy drop" {
		t.Fatal(s)
	}
}
