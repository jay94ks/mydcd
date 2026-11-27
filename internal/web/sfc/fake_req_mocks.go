// SPDX-License-Identifier: Apache-2.0

package sfc

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/jay94ks/seafield/internal/access"
	"github.com/jay94ks/seafield/internal/cluster/control"
)

// TrustRule: a tenant image source (access.TrustRule, the set-trust rule).
type TrustRule = access.TrustRule

// --- REQ-30 ---

func (c *fakeConn) TenantStoragePage(ctx context.Context, tenant, node, after string) (control.TenantStoragePage, error) {
	const m = "tenant-storage"
	if !identifierRE.MatchString(tenant) || node != "" && !identifierRE.MatchString(node) || len(after) > 512 {
		return control.TenantStoragePage{}, fail(m, CodeInvalid, "query")
	}
	user, err := c.lockSession(ctx, m)
	if err != nil {
		return control.TenantStoragePage{}, err
	}
	defer c.unlock()
	w := c.f.w
	if !w.canManage(user, tenant) {
		return control.TenantStoragePage{}, fail(m, CodeDenied, "")
	}
	snap := fakeDigest("tenant-storage-page", tenant, node, fmt.Sprint(w.root))
	snapshot := hex.EncodeToString(snap[:])
	last := ""
	if after != "" {
		prefix, key, ok := strings.Cut(after, ":")
		if !ok || prefix != snapshot {
			return control.TenantStoragePage{}, fail(m, CodeConflict, "after")
		}
		last = key
	}
	rows := slices.Clone(w.nodeStorage)
	slices.SortFunc(rows, func(a, b FixtureStorageRoot) int { return strings.Compare(a.Node+"/"+a.ID, b.Node+"/"+b.ID) })
	out := control.TenantStoragePage{Index: w.root, RootRevision: w.root, Revision: w.root}
	for _, r := range rows {
		key := r.Node + "/" + r.ID
		if key <= last || node != "" && r.Node != node || !slices.Contains(r.Tenants, tenant) || !w.nodeAllowed(tenant, r.Node) {
			continue
		}
		if len(out.Items) == 8 {
			prev := out.Items[len(out.Items)-1]
			out.Next = snapshot + ":" + prev.Node + "/" + prev.ID
			break
		}
		out.Items = append(out.Items, control.TenantStorageRoot{Node: r.Node, ID: r.ID, Generation: max(r.Generation, 1), Revision: r.Revision, Draining: r.Draining, Allowed: true, Root: w.storageRef(r)})
	}
	return out, nil
}

// --- REQ-31 ---

// Fake registry behaviour for image-resolve (ResolveImage): these hosts and
// tags simulate the failure codes once trusted.
const (
	FakeImageAuthFailedHost  = "private.example.com"
	FakeImageUnreachableHost = "unreachable.example.com"
	FakeImageMissingTag      = "missing"
)

// applySetTrust models set-trust: tenant manager (ManageTrust), Expected =
// tenant revision, Add/Remove a delta that must match the current rules.
func (c *fakeConn) applySetTrust(op UserOperation, actor string, next uint64) error {
	w := c.f.w
	var v control.TrustChange
	if decodePayload(op.Change.Payload, &v) != nil || v.Tenant == "" {
		return errors.New("payload")
	}
	if !w.canManage(actor, v.Tenant) {
		return errForbidden
	}
	if op.Change.Expected != w.tenantRev[v.Tenant] {
		return errCAS
	}
	rules := slices.Clone(w.trust[v.Tenant])
	for _, r := range v.Remove {
		i := slices.Index(rules, r)
		if i < 0 {
			return errCAS
		}
		rules = slices.Delete(rules, i, i+1)
	}
	for _, r := range v.Add {
		if slices.Contains(w.trust[v.Tenant], r) {
			return errCAS
		}
		rules = append(rules, r)
	}
	rules, err := access.CanonicalTrust(rules)
	if err != nil || len(v.Add)+len(v.Remove) == 0 {
		return errors.New("payload")
	}
	w.trust[v.Tenant] = rules
	w.tenantRev[v.Tenant] = next
	return nil
}

// --- REQ-23 ---

const (
	raftKeepEntries         = 10240
	raftDefaultMinimal      = 1000
	raftSnapshotBytes       = 6 << 20
	raftBytesPerEntryApprox = 380
)

// HoldCompaction keeps a raft-compact in "running" until released (hold
// false completes it). A second raft-compact while one runs is refused.
func (f *Fake) HoldCompaction(hold bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.w.compactHold = hold
	if !hold {
		f.w.finishCompaction(f.now().Unix())
	}
}

// FailCompaction makes node fail its next compaction with reason.
func (f *Fake) FailCompaction(node, reason string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.w.compactFail == nil {
		f.w.compactFail = map[string]string{}
	}
	f.w.compactFail[node] = reason
}

func (w *world) memberPhase(node string) string {
	for _, m := range w.members {
		if m.ID == node {
			return string(m.Phase)
		}
	}
	return ""
}

func (w *world) finishCompaction(now int64) {
	lc := w.raft.LastCompaction
	if lc == nil {
		return
	}
	keep := uint64(raftKeepEntries)
	if lc.Retain == "minimal" {
		keep = min(lc.Minimal, keep)
	}
	commit := max(w.raft.CommitIndex, w.root)
	for i := range lc.Results {
		r := &lc.Results[i]
		if r.State != "queued" && r.State != "running" {
			continue
		}
		si := slices.IndexFunc(w.raft.Servers, func(s FixtureRaftServer) bool { return s.Node == r.Node })
		s := &w.raft.Servers[si]
		if why, ok := w.compactFail[r.Node]; ok {
			delete(w.compactFail, r.Node)
			r.State, r.Error = "failed", why
			continue
		}
		if p := w.memberPhase(r.Node); p != "" && p != string(NodePhaseActive) {
			r.State, r.Error = "skipped", "server is not responding"
			continue
		}
		before := s.LogEntries
		if before == 0 {
			before = commit - min(commit, max(s.SnapshotIndex, w.raft.LastSnapshotIndex))
		}
		after := min(before, keep)
		r.State, r.SnapshotIndex, r.SnapshotBytes = "done", s.AppliedIndex, raftSnapshotBytes
		r.LogEntriesBefore, r.LogEntriesAfter = before, after
		r.LogBytesBefore = s.LogBytes
		if before > 0 {
			r.LogBytesAfter = s.LogBytes * after / before
		}
		r.LogFileBytes, r.DurationMS = max(s.LogFileBytes, s.LogBytes), 800+int64(i)*150
		s.SnapshotIndex, s.LogEntries, s.LogBytes, s.LogFileBytes = r.SnapshotIndex, after, r.LogBytesAfter, r.LogFileBytes
	}
	w.raft.LastSnapshotIndex, w.raft.LastSnapshotAt = 0, now
	for _, s := range w.raft.Servers {
		w.raft.LastSnapshotIndex = max(w.raft.LastSnapshotIndex, s.SnapshotIndex)
	}
}
