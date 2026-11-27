// SPDX-License-Identifier: Apache-2.0

package app

import (
	"context"
	"errors"
	"io"
	"sync"
	"time"

	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/reconcile"
	"github.com/jay94ks/seafield/internal/storage"
)

// NodeShellStream is the neutral owner boundary used by CLI/SFCP adapters.
// Opening credentials and terminal dimensions come only from the accepted
// operation. This object has no container selector or replacement arguments.
type NodeShellStream struct {
	runtime *Runtime
	native  nodeShellNativeSession
	cancel  context.CancelFunc
	db      *storage.DB
	mu      sync.Mutex
	readMu  sync.Mutex
	writeMu sync.Mutex
	row     control.NodeShellSession
	receipt nodeShellReceipt
	reason  string
	err     error
	done    chan struct{}
}

func (s *NodeShellStream) Metadata() control.NodeShellSession {
	s.mu.Lock()
	defer s.mu.Unlock()
	row := s.row
	if row.End != nil {
		end := *row.End
		if end.ClosedBy != nil {
			actor := *end.ClosedBy
			end.ClosedBy = &actor
		}
		row.End = &end
	}
	return row
}

func (s *NodeShellStream) activity(in, out int) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if in < 0 || out < 0 || uint64(in) > ^uint64(0)-s.receipt.BytesIn || uint64(out) > ^uint64(0)-s.receipt.BytesOut {
		return control.ErrCatalog
	}
	if in > 0 || out > 0 {
		s.receipt.BytesIn += uint64(in)
		s.receipt.BytesOut += uint64(out)
		s.receipt.LastActivity = max(s.receipt.LastActivity, time.Now().Unix())
		s.row.BytesIn, s.row.BytesOut, s.row.LastActivity = s.receipt.BytesIn, s.receipt.BytesOut, s.receipt.LastActivity
	}
	return nil
}

func (s *NodeShellStream) Read(p []byte) (int, error) {
	s.readMu.Lock()
	defer s.readMu.Unlock()
	n, err := s.native.Read(p)
	return n, errors.Join(err, s.activity(0, n))
}

func (s *NodeShellStream) Write(p []byte) (int, error) {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	n, err := s.native.Write(p)
	return n, errors.Join(err, s.activity(n, 0))
}

func (s *NodeShellStream) CloseWrite() error {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	return s.native.CloseWrite()
}
func (s *NodeShellStream) Resize(cols, rows uint16) error {
	if cols == 0 || rows == 0 || cols > 1000 || rows > 1000 {
		return control.ErrCatalog
	}
	return s.native.Resize(cols, rows)
}
func (s *NodeShellStream) Close() error { return s.closeWithReason("exit") }

func (s *NodeShellStream) closeWithReason(reason string) error {
	s.mu.Lock()
	if s.reason == "" {
		s.reason = reason
	}
	s.mu.Unlock()
	err := s.native.Close()
	if s.cancel != nil {
		s.cancel()
	}
	return err
}

func (s *NodeShellStream) Wait() (control.NodeShellEnd, error) {
	<-s.done
	row := s.Metadata()
	if row.End == nil {
		return control.NodeShellEnd{}, reconcile.ErrPending
	}
	s.mu.Lock()
	err := s.err
	s.mu.Unlock()
	return *row.End, err
}

func (s *NodeShellStream) finish() {
	if s.cancel != nil {
		defer s.cancel()
	}
	exit, _ := s.native.Wait()
	m := s.runtime.nodeShell
	m.mu.Lock()
	defer m.mu.Unlock()
	// Wait for byte accounting of any final in-flight read/write. Read and
	// Write have separate locks so interactive input never waits behind Read.
	s.readMu.Lock()
	s.writeMu.Lock()
	s.mu.Lock()
	p := s.receipt
	p.Phase, p.Code, p.Reason = "closed", exit.Code, s.reason
	if p.Reason == "" {
		p.Reason = "exit"
	}
	s.receipt = p
	s.mu.Unlock()
	s.writeMu.Unlock()
	s.readMu.Unlock()
	err := saveNodeShellReceipt(s.db, p)
	var end control.NodeShellEnd
	if err == nil {
		ctx, cancel := context.WithTimeout(s.runtime.ctx, 10*time.Second)
		end, err = s.runtime.publishNodeShellTerminal(ctx, s.db, &p)
		cancel()
	}
	if end.Reason == "" {
		s.mu.Lock()
		if s.row.End != nil {
			end = *s.row.End
			end.Code = p.Code
		} else if p.Reason == "exit" || p.Reason == "idle" {
			end = control.NodeShellEnd{Code: p.Code, Reason: p.Reason}
		}
		s.mu.Unlock()
	}
	// A terminal report whose delivery is only pending stays in the receipt,
	// and the owner reconcile delivers it later; the client still gets the
	// end this daemon saw.
	if end.Reason != "" && errors.Is(err, reconcile.ErrPending) {
		err = nil
	}
	s.mu.Lock()
	s.receipt, s.err = p, err
	s.row.State, s.row.End, s.row.ClosedAt = "closed", &end, time.Now().Unix()
	s.mu.Unlock()
	delete(m.live, p.SessionID)
	close(s.done)
}

func (r *Runtime) publishNodeShellTerminal(ctx context.Context, db *storage.DB, p *nodeShellReceipt) (control.NodeShellEnd, error) {
	if p.Pending != nil {
		err := r.flushNodeShellReport(ctx, db, p)
		if p.Pending != nil {
			return control.NodeShellEnd{}, err
		}
	}
	view, err := r.nodeShellOwnerView(ctx, nil)
	if err != nil {
		return control.NodeShellEnd{}, err
	}
	row, found := view.Book.Record(p.SessionID)
	if !found {
		return control.NodeShellEnd{}, control.ErrCatalog
	}
	if row.Session.State == "closed" {
		return *row.Session.End, nil
	}
	end := control.NodeShellEnd{Code: p.Code, Reason: p.Reason}
	if row.Session.State == "closing" {
		end = *row.Session.End
		end.Code = p.Code
	}
	sequence := uint64(1)
	if row.Report != nil {
		sequence = row.Report.Sequence + 1
	}
	report := r.signNodeShellReport(view, control.NodeShellReport{Kind: "closed", SessionID: p.SessionID, At: time.Now().Unix(), LastActivity: p.LastActivity, BytesIn: p.BytesIn, BytesOut: p.BytesOut, Sequence: sequence, Code: p.Code, Reason: end.Reason})
	p.Pending = &report
	if err := saveNodeShellReceipt(db, *p); err != nil {
		return end, err
	}
	return end, r.flushNodeShellReport(ctx, db, p)
}

// closeNodeShells must finish before observations.db is closed. An exclusive
// reopen of that DB can therefore prove an older daemon instance no longer
// owns an SSH transport: clean Close closed it first, or OS process death
// released the lock and its descriptors. Missing in-memory handles within the
// SAME instance never serve as such proof.
func (r *Runtime) closeNodeShells() {
	m := r.nodeShell
	if m == nil {
		return
	}
	m.mu.Lock()
	m.closed = true
	var live []*NodeShellStream
	for _, session := range m.live {
		live = append(live, session)
	}
	m.mu.Unlock()
	for _, session := range live {
		_ = session.Close()
	}
	m.wg.Wait()
}

var _ io.ReadWriteCloser = (*NodeShellStream)(nil)
