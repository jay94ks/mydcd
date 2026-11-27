// SPDX-License-Identifier: Apache-2.0

package app

import (
	"bytes"
	"context"
	"errors"
	"io"
	"sync"
	"testing"

	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/nodeshell"
)

type nodeShellStreamFake struct {
	input, output bytes.Buffer
	mu            sync.Mutex
	closed, eof   bool
	cols, rows    uint16
}

func (f *nodeShellStreamFake) Read(p []byte) (int, error)  { return f.output.Read(p) }
func (f *nodeShellStreamFake) Write(p []byte) (int, error) { return f.input.Write(p) }
func (f *nodeShellStreamFake) CloseWrite() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.eof = true
	return nil
}
func (f *nodeShellStreamFake) Resize(c, r uint16) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.cols, f.rows = c, r
	return nil
}
func (f *nodeShellStreamFake) Close() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.closed = true
	return nil
}
func (f *nodeShellStreamFake) Wait() (nodeshell.Exit, error) { return nodeshell.Exit{Code: 7}, nil }

func TestNodeShellStreamAccountsActualBytesAndKeepsOriginalActor(t *testing.T) {
	f := &nodeShellStreamFake{}
	f.output.WriteString("response")
	ctx, cancel := context.WithCancel(context.Background())
	s := &NodeShellStream{native: f, cancel: cancel, receipt: nodeShellReceipt{LastActivity: 10}, row: control.NodeShellSession{SessionID: "original", Username: "alice", LastActivity: 10, State: "opened"}}
	if n, err := s.Write([]byte("cmd")); n != 3 || err != nil {
		t.Fatal(n, err)
	}
	buf := make([]byte, 32)
	if n, err := s.Read(buf); n != 8 || err != nil || string(buf[:n]) != "response" {
		t.Fatal(n, err)
	}
	before := s.Metadata()
	if before.BytesIn != 3 || before.BytesOut != 8 || before.LastActivity < 10 {
		t.Fatal("actual bytes lost", before)
	}
	if n, err := s.Read(buf); n != 0 || !errors.Is(err, io.EOF) {
		t.Fatal(n, err)
	}
	if after := s.Metadata(); after.LastActivity != before.LastActivity {
		t.Fatal("empty read fabricated activity")
	}
	if err := s.Resize(0, 24); err == nil {
		t.Fatal("invalid dimensions reached SSH")
	}
	if err := s.Resize(100, 40); err != nil || f.cols != 100 || f.rows != 40 {
		t.Fatal("PTY resize lost", err)
	}
	if err := s.CloseWrite(); err != nil || !f.eof {
		t.Fatal("EOF lost", err)
	}
	actor := &control.NodeShellUser{User: "admin-id", Username: "admin"}
	s.mu.Lock()
	s.row.End = &control.NodeShellEnd{Reason: "policy", ClosedBy: actor}
	s.mu.Unlock()
	metadata := s.Metadata()
	metadata.End.ClosedBy.User = "forged"
	if s.Metadata().End.ClosedBy.User != "admin-id" {
		t.Fatal("caller mutated original closing actor")
	}
	if err := s.closeWithReason("policy"); err != nil || !f.closed {
		t.Fatal("policy did not close original SSH", err)
	}
	if ctx.Err() == nil {
		t.Fatal("original connection context not cancelled")
	}
	if s.Metadata().State != "opened" {
		t.Fatal("requesting close fabricated closed proof")
	}
	if s.reason != "policy" {
		t.Fatal("stored close reason lost")
	}
}

func TestNodeShellStreamRejectsCounterOverflowWithoutMutation(t *testing.T) {
	s := &NodeShellStream{receipt: nodeShellReceipt{BytesIn: ^uint64(0), BytesOut: 4, LastActivity: 10}}
	if err := s.activity(1, 0); err == nil {
		t.Fatal("counter overflow accepted")
	}
	if s.receipt.BytesIn != ^uint64(0) || s.receipt.BytesOut != 4 || s.receipt.LastActivity != 10 {
		t.Fatal("failed accounting mutated receipt")
	}
	if err := s.activity(-1, 0); err == nil {
		t.Fatal("negative adapter byte count accepted")
	}
}
