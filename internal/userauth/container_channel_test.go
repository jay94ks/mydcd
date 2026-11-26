// SPDX-License-Identifier: Apache-2.0

package userauth

import (
	"context"
	"errors"
	"io"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jay94ks/mydcd/internal/containerops"
	quic "github.com/quic-go/quic-go"
)

type partialContainerFrame struct{ writes atomic.Int32 }

func (*partialContainerFrame) Read([]byte) (int, error) { return 0, io.EOF }
func (s *partialContainerFrame) Write([]byte) (int, error) {
	s.writes.Add(1)
	return 1, io.ErrClosedPipe
}
func (*partialContainerFrame) Close() error                     { return nil }
func (*partialContainerFrame) SetDeadline(time.Time) error      { return nil }
func (*partialContainerFrame) SetReadDeadline(time.Time) error  { return nil }
func (*partialContainerFrame) SetWriteDeadline(time.Time) error { return nil }
func (*partialContainerFrame) CancelRead(quic.StreamErrorCode)  {}
func (*partialContainerFrame) CancelWrite(quic.StreamErrorCode) {}

func TestContainerChannelPartialFrameEndsIOWithoutSendingAnotherRecord(t *testing.T) {
	// Same validated intent as the real wire test; only the writer fails.
	_, c, session, node := journalFixture(t)
	i := containerops.SessionIntent{Schema: 1, Request: "partial-original", User: session.User, Session: [32]byte{1}, At: time.Now().Unix(), Target: containerops.Target{Cluster: c.Cluster, Owner: node.Public, Binding: [32]byte{1}, Tenant: "tenant", App: "app", Service: "web", Node: "node-a", Instance: "task", Generation: 1, Revision: 1, NativeID: "original", StartedAt: "2026-01-01T00:00:00Z"}, Spec: containerops.SessionSpec{Kind: "exec", Exec: &containerops.ExecSpec{Argv: []string{"tool"}}}}
	stream := &partialContainerFrame{}
	channel, err := newContainerChannel(context.Background(), nil, stream, 1, i, session.ExpiresAt, false)
	if err != nil {
		t.Fatal(err)
	}
	defer channel.Close()
	if err = channel.Send(containerops.SessionRecord{Kind: "stdout", Data: []byte("bounded output")}); !errors.Is(err, io.ErrClosedPipe) {
		t.Fatal("partial frame failure lost", err)
	}
	if err = channel.Send(containerops.SessionRecord{Kind: "end"}); !errors.Is(err, context.Canceled) || stream.writes.Load() != 1 {
		t.Fatal("sent a second record after a partial frame", err, stream.writes.Load())
	}
}
