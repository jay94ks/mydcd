// SPDX-License-Identifier: Apache-2.0

package app

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/jay94ks/mydcd/internal/access"
	"github.com/jay94ks/mydcd/internal/cluster/control"
	"github.com/jay94ks/mydcd/internal/cluster/state"
	"github.com/jay94ks/mydcd/internal/reconcile"
	"github.com/jay94ks/mydcd/internal/schema"
	"github.com/jay94ks/mydcd/internal/storage"
)

const nodeShellReadyReceiptKey = "node-shell/readiness"

// nodeShellQuietRecheck bounds how long a quiet node goes without asking the
// leader. Quiet means node shell is off for this node, nothing is open or
// queued for it and no report is waiting; only a change of the replicated
// node-shell root can end that, and it reaches this node as a local FSM change.
const nodeShellQuietRecheck = time.Minute

func (r *Runtime) nodeShellLoop() {
	var settled nodeShellRoot
	var settledAt time.Time
	for {
		changed := r.Engine().Changes()
		root, quiet := r.nodeShellQuiet()
		if !quiet || root != settled || time.Since(settledAt) >= nodeShellQuietRecheck {
			ctx, cancel := context.WithTimeout(r.ctx, 15*time.Second)
			err := r.reconcileNodeShells(ctx)
			cancel()
			r.nodeShell.mu.Lock()
			r.nodeShell.err = err
			r.nodeShell.mu.Unlock()
			settled = nodeShellRoot{}
			if err == nil && quiet {
				// The leader's current view agreed with the quiet local one.
				settled, settledAt = root, time.Now()
			}
		}
		if !waitModulePass(r.ctx, changed, false, 2*time.Second) {
			return
		}
	}
}

type nodeShellRoot struct{ Epoch, Revision uint64 }

// nodeShellQuiet reports, from the local replica only, whether a pass would
// have nothing to do but confirm that node shell stays off for this node.
func (r *Runtime) nodeShellQuiet() (nodeShellRoot, bool) {
	m := r.nodeShell
	view, err := r.Engine().Read(r.ctx, false)
	if err != nil {
		return nodeShellRoot{}, false
	}
	book, err := r.controlPolicy.NodeShells(view.State)
	if err != nil {
		return nodeShellRoot{}, false
	}
	root := nodeShellRoot{Epoch: view.State.ModuleEpoch(), Revision: view.State.Object(control.NodeShellKey).Revision}
	if _, err := r.reports.GetBounded(nodeShellReadyReceiptKey, 8192); !errors.Is(err, storage.ErrMissing) {
		return root, false
	}
	m.mu.Lock()
	idle := len(m.live) == 0 && !m.prepared && !m.closed
	m.mu.Unlock()
	return root, idle && nodeShellBookQuiet(book, m.node)
}

// nodeShellBookQuiet reports whether node shell is off for node and no
// session for it is still open, closing or queued.
func nodeShellBookQuiet(book control.NodeShellBook, node string) bool {
	if _, enabled := book.Policy.Node(node); enabled {
		return false
	}
	for _, row := range book.Records {
		if row.Session.Node == node && row.Session.State != "closed" {
			return false
		}
	}
	return true
}

func (r *Runtime) NodeShellError() error {
	if r.nodeShell == nil {
		return nil
	}
	r.nodeShell.mu.Lock()
	defer r.nodeShell.mu.Unlock()
	return r.nodeShell.err
}

// The one owner pass is serialized with stream admission. It never opens a
// queued SSH job: only the authenticated stream consumer calls OpenNodeShell.
func (r *Runtime) reconcileNodeShells(ctx context.Context) error {
	m := r.nodeShell
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed || r.historicalOwner {
		return nil
	}
	view, err := r.nodeShellOwnerView(ctx, nil)
	if err != nil {
		// An unavailable current decision cannot extend an accepted session's
		// authority. Closing the transport preserves its original receipt and
		// pending report; it never grants permission to open another SSH.
		for _, live := range m.live {
			err = errors.Join(err, live.closeWithReason("exit"))
		}
		return err
	}
	node, enabled := view.Book.Policy.Node(m.node)
	var failed error
	if !enabled {
		failed = m.native.RevokeSudo(ctx)
		m.prepared = false
	} else {
		failed = r.advanceNodeShellReadiness(ctx, view, node.Sudo)
	}
	for _, row := range view.Book.Records {
		if row.Session.Node != m.node || row.Session.State == "closed" {
			continue
		}
		if live := m.live[row.Session.SessionID]; live != nil {
			if row.Session.State == "closing" {
				live.mu.Lock()
				end := *row.Session.End
				live.row.End = &end
				live.mu.Unlock()
				failed = errors.Join(failed, live.closeWithReason(end.Reason))
				continue
			}
			// Continuation uses the same current authorization core as admission.
			// Expiry, issuer removal or an unavailable current decision must not
			// turn an old accepted grant into an indefinitely usable shell.
			if _, err := r.nodeShellPermit(ctx, row.Session.SessionID); err != nil {
				failed = errors.Join(failed, err, live.closeWithReason("exit"))
				continue
			}
			live.mu.Lock()
			p := live.receipt
			live.mu.Unlock()
			if row.Session.State == "opened" && time.Now().Unix()-p.LastActivity >= int64(view.Book.Policy.IdleSeconds) {
				failed = errors.Join(failed, live.closeWithReason("idle"))
				continue
			}
			if p.Pending != nil {
				failed = errors.Join(failed, r.flushNodeShellReport(ctx, live.db, &p))
				live.mu.Lock()
				live.receipt.Pending = p.Pending
				live.mu.Unlock()
				continue
			}
			if row.Session.State != "opened" || p.BytesIn == row.Session.BytesIn && p.BytesOut == row.Session.BytesOut || row.Report != nil && time.Now().Unix()-row.Report.At < 10 {
				continue
			}
			fresh, err := r.nodeShellOwnerView(ctx, nil)
			if err != nil {
				failed = errors.Join(failed, err)
				continue
			}
			current, found := fresh.Book.Record(p.SessionID)
			if !found || current.Session.State != "opened" {
				continue
			}
			sequence := uint64(1)
			if current.Report != nil {
				sequence = current.Report.Sequence + 1
			}
			report := r.signNodeShellReport(fresh, control.NodeShellReport{Kind: "activity", SessionID: p.SessionID, At: time.Now().Unix(), LastActivity: p.LastActivity, BytesIn: p.BytesIn, BytesOut: p.BytesOut, Sequence: sequence})
			p.Pending = &report
			if err := saveNodeShellReceipt(live.db, p); err != nil {
				failed = errors.Join(failed, err)
				continue
			}
			failed = errors.Join(failed, r.flushNodeShellReport(ctx, live.db, &p))
			live.mu.Lock()
			// Incoming bytes may have advanced while the bounded report RPC
			// ran. Never overwrite their newer counters/activity with p.
			live.receipt.Pending = p.Pending
			live.mu.Unlock()
			continue
		}
		p, db, exists, err := r.nodeShellReceipt(row)
		if err != nil {
			failed = errors.Join(failed, err)
			continue
		}
		if !exists {
			if row.Session.State != "closing" || row.Session.OpenedAt != 0 {
				continue
			}
			// Every native Open must first sync its original sent receipt.
			// Under the same exclusive DB lock/admission mutex, an unsubmitted
			// queued close can settle without claiming a native ever opened.
			p = nodeShellReceipt{Schema: 1, Cluster: r.controlPolicy.Cluster, Owner: row.Owner, Origin: nodeShellOrigin(row), Instance: m.instance, Node: m.node, SessionID: row.Session.SessionID, Phase: "closed", Reason: row.Session.End.Reason}
		} else if p.Phase != "closed" {
			if p.Instance == m.instance {
				// Same-instance lost handle is unknown, not closure evidence.
				failed = errors.Join(failed, reconcile.ErrPending)
				continue
			}
			// These original DBs were exclusively reopened after the prior
			// daemon ended. Clean shutdown closes its SSH transports before
			// releasing them; process death closes its descriptors itself.
			p.Phase, p.Code, p.Reason = "closed", 255, "exit"
		}
		if err := saveNodeShellReceipt(db, p); err != nil {
			failed = errors.Join(failed, err)
			continue
		}
		_, err = r.publishNodeShellTerminal(ctx, db, &p)
		failed = errors.Join(failed, err)
	}
	return failed
}

func (r *Runtime) advanceNodeShellReadiness(ctx context.Context, view nodeShellOwnerSnapshot, allowSudo bool) error {
	m := r.nodeShell
	raw, err := r.reports.GetBounded(nodeShellReadyReceiptKey, 8192)
	if err == nil {
		pending, err := schema.Decode[control.NodeShellReport](raw)
		if err != nil || pending.Kind != "ready" || pending.Node != m.node || pending.Cluster != r.controlPolicy.Cluster {
			return control.ErrCatalog
		}
		// Reconcile the exact original observation first. Changed policy/key is
		// not proof that an earlier delivery never submitted.
		checked, err := r.nodeShellOwnerView(ctx, &pending)
		if err != nil {
			return err
		}
		result := checked.Result
		if result == nil && !checked.Rejected {
			result, err = r.sendNodeShellReport(ctx, pending)
			if err != nil || result == nil {
				return errors.Join(reconcile.ErrPending, err)
			}
		}
		if result == nil && !checked.Rejected {
			return reconcile.ErrPending
		}
		if result == nil || result.Code != state.Applied {
			// Preserve a superseded unknown or known terminal rejection, never
			// relabeling an earlier delivery NotSent from result absence.
			if err := saveNodeShellReadyRetirement(r.reports, pending, result); err != nil {
				return err
			}
		} else if err := r.reports.Write(map[string][]byte{nodeShellReadyReceiptKey: nil}); err != nil {
			return err
		}
		return nil
	} else if !errors.Is(err, storage.ErrMissing) {
		return err
	}
	var sequence uint64 = 1
	var last int64
	for _, ready := range view.Book.Readiness {
		if ready.Node == m.node {
			sequence, last = ready.Sequence+1, ready.At
		}
	}
	if m.prepared && m.preparedRevision == view.Book.Policy.Revision && time.Now().Unix()-last < 10 {
		return nil
	}
	ready := m.native.Prepare(ctx, allowSudo)
	if ready.Ready && (ready.Account != access.NodeShellAccount || ready.SudoAllowed != allowSudo) {
		m.prepared = false
		return control.ErrCatalog
	}
	fresh, err := r.nodeShellOwnerView(ctx, nil)
	if err != nil {
		return err
	}
	if fresh.Book.Policy.Revision != view.Book.Policy.Revision {
		_ = m.native.RevokeSudo(ctx)
		m.prepared = false
		return reconcile.ErrPending
	}
	// Readiness snapshots carry the actual effective sudo policy even when
	// the adapter is not ready and its public SudoAllowed remains false.
	notReady := ready.Reason
	if ready.Ready {
		notReady = ""
	}
	report := r.signNodeShellReport(fresh, control.NodeShellReport{Kind: "ready", At: time.Now().Unix(), Sequence: sequence, Ready: ready.Ready, NotReady: notReady, Sudo: allowSudo})
	raw, _ = json.Marshal(report)
	if err := r.reports.Write(map[string][]byte{nodeShellReadyReceiptKey: raw}); err != nil {
		return err
	}
	m.prepared, m.preparedRevision = ready.Ready, fresh.Book.Policy.Revision
	result, err := r.sendNodeShellReport(ctx, report)
	if err != nil || result == nil {
		return errors.Join(reconcile.ErrPending, err)
	}
	if err := r.reports.Write(map[string][]byte{nodeShellReadyReceiptKey: nil}); err != nil {
		return err
	}
	if result.Code != state.Applied {
		return reconcile.ErrPending
	}
	return nil
}
