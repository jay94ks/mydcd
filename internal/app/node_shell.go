// SPDX-License-Identifier: Apache-2.0

package app

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"sync"
	"time"

	"github.com/jay94ks/mydcd/internal/cluster"
	"github.com/jay94ks/mydcd/internal/cluster/control"
	"github.com/jay94ks/mydcd/internal/cluster/state"
	"github.com/jay94ks/mydcd/internal/config"
	"github.com/jay94ks/mydcd/internal/identity"
	"github.com/jay94ks/mydcd/internal/nodeshell"
	"github.com/jay94ks/mydcd/internal/reconcile"
	"github.com/jay94ks/mydcd/internal/schema"
	"github.com/jay94ks/mydcd/internal/storage"
)

type nodeShellNativeSession interface {
	io.ReadWriteCloser
	CloseWrite() error
	Resize(uint16, uint16) error
	Wait() (nodeshell.Exit, error)
}
type nodeShellNative interface {
	Prepare(context.Context, bool) nodeshell.PublicReady
	RevokeSudo(context.Context) error
	Open(context.Context, uint16, uint16, string) (nodeShellNativeSession, error)
}
type nodeShellAdapter struct{ *nodeshell.Adapter }

func (a nodeShellAdapter) Open(ctx context.Context, cols, rows uint16, name string) (nodeShellNativeSession, error) {
	return a.Adapter.Open(ctx, cols, rows, name)
}

type nodeShellRuntime struct {
	mu               sync.Mutex
	node             string
	instance         [32]byte
	native           nodeShellNative
	live             map[string]*NodeShellStream
	closed           bool
	err              error
	prepared         bool
	preparedRevision uint64
	wg               sync.WaitGroup
}

// openNodeShell is called once on the current logical Runtime after its
// historical observation stores have acquired their original exclusive locks.
// Account/key provisioning remains deferred until the own-node policy enables
// it. Historical native owners never create their own SSH account/worker.
func (r *Runtime) openNodeShell(node, stateRoot string, shell config.NodeShell) error {
	if r.historicalOwner {
		return nil
	}
	adapter, err := nodeshell.New(nodeshell.Config{StateDir: filepath.Join(stateRoot, "node-shell"), Endpoint: shell.SSHEndpoint, HostPublicKeyFile: shell.HostPublicKey, Home: shell.Home, SudoersDir: shell.SudoersDir})
	if err != nil {
		return err
	}
	m := &nodeShellRuntime{node: node, native: nodeShellAdapter{adapter}, live: map[string]*NodeShellStream{}}
	if _, err := rand.Read(m.instance[:]); err != nil {
		return err
	}
	r.nodeShell = m
	r.wg.Add(1)
	go func() {
		defer r.wg.Done()
		defer r.closeNodeShells()
		r.nodeShellLoop()
	}()
	return nil
}

type nodeShellOwnerRequest struct {
	Node   string
	Report *control.NodeShellReport `json:",omitempty"`
}
type nodeShellOwnerSnapshot struct {
	Book                control.NodeShellBook
	Epoch, RootRevision uint64
	Result              *state.Result `json:",omitempty"`
	Rejected            bool          `json:",omitempty"`
}
type nodeShellPermitRequest struct{ SessionID string }

// These two callbacks are registered by readModule as authenticated MYDCP
// owner reads. The caller receives the leader's current view, not a local
// permission inferred from a stale replicated policy.
func (r *Runtime) nodeShellOwnerRead(key string, raw []byte, v cluster.View) ([]byte, error) {
	caller, err := identity.ParseKey(key)
	q, decodeErr := schema.Decode[nodeShellOwnerRequest](raw)
	if err != nil || decodeErr != nil || v.Local {
		return nil, control.ErrCatalog
	}
	book, err := r.controlPolicy.NodeShellOwner(v.State, caller, q.Node)
	if err != nil {
		return nil, err
	}
	out := nodeShellOwnerSnapshot{Book: book, Epoch: v.State.ModuleEpoch(), RootRevision: v.State.Object(control.NodeShellKey).Revision}
	if q.Report != nil {
		if q.Report.Node != q.Node {
			return nil, control.ErrCatalog
		}
		command, err := q.Report.Command()
		if err != nil {
			return nil, err
		}
		if result, found := v.State.LookupResult(command); found {
			out.Result = &result
		} else {
			raw, _ := json.Marshal(q.Report)
			_, err := r.controlPolicy.ResolveNodeShellReport(v.State, caller, raw)
			out.Rejected = err != nil
		}
	}
	return json.Marshal(out)
}

func (r *Runtime) nodeShellPermitRead(key string, raw []byte, v cluster.View) ([]byte, error) {
	caller, err := identity.ParseKey(key)
	q, decodeErr := schema.Decode[nodeShellPermitRequest](raw)
	if err != nil || decodeErr != nil || v.Local {
		return nil, control.ErrCatalog
	}
	permit, err := r.controlPolicy.NodeShellPermit(v.State, caller, q.SessionID, time.Now().Unix())
	if err != nil {
		return nil, err
	}
	return json.Marshal(permit)
}

func (r *Runtime) nodeShellOwnerView(ctx context.Context, pending *control.NodeShellReport) (nodeShellOwnerSnapshot, error) {
	if err := ctx.Err(); err != nil {
		return nodeShellOwnerSnapshot{}, err
	}
	raw, _ := json.Marshal(nodeShellOwnerRequest{Node: r.nodeShell.node, Report: pending})
	reply, err := r.appCall(ctx, "node-shell-owner-view", raw)
	if err != nil || reply.Local {
		return nodeShellOwnerSnapshot{}, errors.Join(reconcile.ErrPending, err)
	}
	view, err := schema.Decode[nodeShellOwnerSnapshot](reply.Data)
	if err != nil || view.Book.Cluster != r.controlPolicy.Cluster || view.Epoch == 0 {
		return view, control.ErrCatalog
	}
	return view, nil
}

func (r *Runtime) nodeShellPermit(ctx context.Context, id string) (control.NodeShellPermit, error) {
	if err := ctx.Err(); err != nil {
		return control.NodeShellPermit{}, err
	}
	raw, _ := json.Marshal(nodeShellPermitRequest{SessionID: id})
	reply, err := r.appCall(ctx, "node-shell-permit", raw)
	if err != nil || reply.Local {
		return control.NodeShellPermit{}, errors.Join(reconcile.ErrPending, err)
	}
	permit, err := schema.Decode[control.NodeShellPermit](reply.Data)
	if err != nil || permit.Record.Owner != r.Identity.Public || permit.Record.Session.Node != r.nodeShell.node {
		return permit, control.ErrCatalog
	}
	return permit, nil
}

func (r *Runtime) signNodeShellReport(view nodeShellOwnerSnapshot, report control.NodeShellReport) control.NodeShellReport {
	report.Schema, report.Cluster, report.Reporter = 1, r.controlPolicy.Cluster, r.commandIdentity().Public
	report.Node, report.Epoch, report.RootRevision = r.nodeShell.node, view.Epoch, view.RootRevision
	report.PolicyRevision = view.Book.Policy.Revision
	digest := sha256.Sum256(control.NodeShellReportBytes(report))
	report.RequestID = fmt.Sprintf("node-shell/%x", digest)
	report.Signature = ed25519.Sign(r.commandIdentity().Private, control.NodeShellReportBytes(report))
	return report
}

func (r *Runtime) sendNodeShellReport(ctx context.Context, report control.NodeShellReport) (*state.Result, error) {
	if r.Engine().IsLeader() {
		command, err := report.Command()
		if err != nil {
			return nil, err
		}
		committed, err := r.Engine().Submit(ctx, command)
		if err != nil {
			return nil, err
		}
		return &committed.Result, nil
	}
	raw, _ := json.Marshal(report)
	reply, err := r.appCall(ctx, "node-shell-report", raw)
	if err != nil || reply.Committed == nil {
		return nil, errors.Join(reconcile.ErrPending, err)
	}
	return &reply.Committed.Result, nil
}

// One outstanding report is retained and retried with its original signature
// and ID after an unknown reply. This never retries the original SSH effect.
func (r *Runtime) flushNodeShellReport(ctx context.Context, db *storage.DB, receipt *nodeShellReceipt) error {
	// At most one observation replacement is delivered in this pass. No branch
	// calls native.Open, and an absent result/unknown transport is not evidence
	// permitting a replacement of the original pending delivery.
	for attempt := 0; attempt < 2 && receipt.Pending != nil; attempt++ {
		view, err := r.nodeShellOwnerView(ctx, receipt.Pending)
		if err != nil {
			return err
		}
		result := view.Result
		if result == nil && !view.Rejected {
			result, err = r.sendNodeShellReport(ctx, *receipt.Pending)
			if err != nil || result == nil {
				return errors.Join(reconcile.ErrPending, err)
			}
		}
		if result != nil && result.Code == state.Applied {
			// Re-read the original record after a delivered reply before using
			// its accepted sequence/counters for any following observation.
			fresh, err := r.nodeShellOwnerView(ctx, receipt.Pending)
			if err != nil {
				return err
			}
			row, found := fresh.Book.Record(receipt.SessionID)
			if !found || !receipt.valid(r.controlPolicy.Cluster, row) {
				return control.ErrCatalog
			}
			next := *receipt
			next.Pending = nil
			if err := saveNodeShellReceipt(db, next); err != nil {
				return err
			}
			*receipt = next
			return nil
		}
		// A current pre-submit rejection is NOT proof that earlier delivery
		// never submitted. Its original signed unknown observation is archived
		// below before a positive current observation may replace Pending.
		fresh, err := r.nodeShellOwnerView(ctx, receipt.Pending)
		if err != nil {
			return err
		}
		if fresh.Result != nil && fresh.Result.Code == state.Applied {
			row, found := fresh.Book.Record(receipt.SessionID)
			if !found || !receipt.valid(r.controlPolicy.Cluster, row) {
				return control.ErrCatalog
			}
			next := *receipt
			next.Pending = nil
			if err := saveNodeShellReceipt(db, next); err != nil {
				return err
			}
			*receipt = next
			return nil
		}
		if fresh.Result != nil {
			result = fresh.Result
		}
		if !nodeShellObservationReplaceable(fresh, result) {
			return reconcile.ErrPending
		}
		report, needed, err := nodeShellNextObservation(*receipt, fresh, r.commandIdentity().Public, time.Now().Unix())
		if err != nil {
			return err
		}
		next := *receipt
		next.Pending = nil
		if needed {
			signed := r.signNodeShellReport(fresh, report)
			next.Pending = &signed
		}
		if err := saveNodeShellObservationReplacement(db, *receipt, next, result); err != nil {
			return err
		}
		*receipt = next
	}
	if receipt.Pending != nil {
		return reconcile.ErrPending
	}
	return nil
}

// OpenNodeShell consumes one already accepted original operation. A repeated
// stream request cannot create a second native connection, even if the first
// SSH-open acknowledgement or the owner report was lost.
func (r *Runtime) OpenNodeShell(ctx context.Context, id string) (*NodeShellStream, error) {
	m := r.nodeShell
	if m == nil || r.historicalOwner || r.ctx.Err() != nil {
		return nil, control.ErrNodeShellNotReady
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed || m.live[id] != nil {
		return nil, reconcile.ErrPending
	}
	permit, err := r.nodeShellPermit(ctx, id)
	if err != nil {
		return nil, err
	}
	row := permit.Record
	if !m.prepared || m.preparedRevision != permit.PolicyRevision {
		return nil, control.ErrNodeShellNotReady
	}
	p, db, exists, err := r.nodeShellReceipt(row)
	if err != nil || exists || row.Session.State != "queued" {
		return nil, errors.Join(reconcile.ErrPending, err)
	}
	p = nodeShellReceipt{Schema: 1, Cluster: r.controlPolicy.Cluster, Owner: row.Owner, Origin: nodeShellOrigin(row), Instance: m.instance, Node: m.node, SessionID: id, Phase: "sent"}
	if err := saveNodeShellReceipt(db, p); err != nil {
		return nil, err
	}
	// Native lifetime is the daemon's, not the admitting RPC's. The returned
	// stream's Close handles caller disconnection without rebinding the ID.
	nativeCtx, cancelNative := context.WithCancel(r.ctx)
	stopAdmission := context.AfterFunc(ctx, cancelNative)
	native, openErr := m.native.Open(nativeCtx, row.Cols, row.Rows, row.Session.Username)
	stopAdmission()
	if openErr == nil && ctx.Err() != nil {
		_ = native.Close()
		_, _ = native.Wait()
		openErr = ctx.Err()
	}
	if openErr != nil {
		cancelNative()
		// The native adapter returns failures only after closing any connection
		// it may have created. No successful-open fact is fabricated.
		p.Phase, p.Code, p.Reason = "closed", 255, "exit"
		_ = saveNodeShellReceipt(db, p)
		return nil, openErr
	}
	now := time.Now().Unix()
	p.Phase, p.OpenedAt, p.LastActivity = "opened", now, now
	if err := saveNodeShellReceipt(db, p); err != nil {
		cancelNative()
		_ = native.Close()
		_, _ = native.Wait()
		return nil, err
	}
	live := &NodeShellStream{runtime: r, native: native, cancel: cancelNative, row: row.Session, receipt: p, db: db, done: make(chan struct{})}
	live.row.OpenedAt, live.row.LastActivity, live.row.State = now, now, "opened"
	m.live[id] = live
	m.wg.Add(1)
	go func() { defer m.wg.Done(); live.finish() }()
	view, err := r.nodeShellOwnerView(ctx, nil)
	if err == nil {
		report := r.signNodeShellReport(view, control.NodeShellReport{Kind: "opened", SessionID: id, At: now, LastActivity: now, Sequence: 1})
		p.Pending = &report
		err = saveNodeShellReceipt(db, p)
		if err == nil {
			err = r.flushNodeShellReport(ctx, db, &p)
		}
		live.mu.Lock()
		live.receipt = p
		live.mu.Unlock()
		// The signed "opened" report is kept in the receipt. When only its
		// delivery is pending (another report moved the root under it), the
		// owner reconcile delivers it later; the open shell stays.
		if p.Pending != nil && errors.Is(err, reconcile.ErrPending) {
			err = nil
		}
	}
	if err != nil {
		_ = live.Close()
		return nil, err
	}
	return live, nil
}
