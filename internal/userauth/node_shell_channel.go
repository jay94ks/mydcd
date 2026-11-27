// SPDX-License-Identifier: Apache-2.0

package userauth

import (
	"context"
	"sync"
	"sync/atomic"
	"time"

	"github.com/jay94ks/seafield/internal/sfcp"
)

// NodeShellChannel serializes bounded records on one authenticated original
// intent. Receive has one owner; Send may be shared by output/heartbeat.
type NodeShellChannel struct {
	ctx            context.Context
	cancel         context.CancelFunc
	stop           func() bool
	stopped        chan struct{}
	conn           *sfcp.Session
	stream         sfcp.DuplexStream
	request        uint64
	intent         [32]byte
	client         bool
	sendMu         sync.Mutex
	sent, received sfcp.NodeShellFlow
	release        sync.Once
	receiveStopped atomic.Bool
}

func newNodeShellChannel(ctx context.Context, conn *sfcp.Session, stream sfcp.Stream, request uint64, intent [32]byte, expires int64, client bool) (*NodeShellChannel, error) {
	duplex, ok := stream.(sfcp.DuplexStream)
	if !ok || intent == ([32]byte{}) {
		return nil, sfcp.ErrAdmission
	}
	ctx, cancel := context.WithDeadline(ctx, time.Unix(expires, 0))
	c := &NodeShellChannel{ctx: ctx, cancel: cancel, conn: conn, stream: duplex, request: request, intent: intent, client: client, stopped: make(chan struct{}), sent: sfcp.NodeShellFlow{}, received: sfcp.NodeShellFlow{}}
	if err := stream.SetDeadline(time.Time{}); err != nil {
		cancel()
		return nil, err
	}
	c.stop = context.AfterFunc(ctx, func() { stream.CancelRead(1); stream.CancelWrite(1); close(c.stopped) })
	return c, nil
}

func (c *NodeShellChannel) Context() context.Context { return c.ctx }
func (c *NodeShellChannel) Receive() (sfcp.NodeShellRecord, error) {
	var zero sfcp.NodeShellRecord
	if c.receiveStopped.Load() {
		return zero, context.Canceled
	}
	if err := c.ctx.Err(); err != nil {
		return zero, err
	}
	if err := c.stream.SetReadDeadline(time.Now().Add(60 * time.Second)); err != nil {
		return zero, err
	}
	if c.receiveStopped.Load() {
		_ = c.stream.SetReadDeadline(time.Now())
	}
	r, err := sfcp.ReadNodeShellRecord(c.stream, c.request, c.intent)
	if err != nil {
		return zero, err
	}
	if err = c.conn.Admit(sfcp.Frame{Purpose: sfcp.NodeShell, Kind: 5}, sfcp.NodeShell, false); err != nil {
		return zero, err
	}
	next, err := c.received.Accept(r, !c.client)
	if err != nil {
		return zero, err
	}
	c.received = next
	return r, nil
}
func (c *NodeShellChannel) Send(r sfcp.NodeShellRecord) error {
	c.sendMu.Lock()
	defer c.sendMu.Unlock()
	if err := c.ctx.Err(); err != nil {
		return err
	}
	r.Schema, r.Sequence = 1, c.sent.Sequence+1
	next, err := c.sent.Accept(r, c.client)
	if err != nil {
		return err
	}
	if err = c.stream.SetWriteDeadline(time.Now().Add(5 * time.Second)); err != nil {
		c.cancel()
		return err
	}
	if err = sfcp.WriteNodeShellRecord(c.stream, c.request, c.intent, r); err != nil {
		// A partial frame cannot be followed by a fresh frame/sequence on
		// the same byte stream. Close this I/O lifetime; status uses its
		// separate original-ID request and never retries this send.
		c.cancel()
		return err
	}
	c.sent = next
	return nil
}

// StopReceive interrupts only the reader so its goroutine can be joined after
// process output ends. The server may still send its final receipt/end record.
func (c *NodeShellChannel) StopReceive() {
	c.receiveStopped.Store(true)
	_ = c.stream.SetReadDeadline(time.Now())
}

// releaseContext leaves normal EOF/connection ownership to the transport.
func (c *NodeShellChannel) releaseContext() {
	c.release.Do(func() {
		if !c.stop() {
			<-c.stopped
		}
		c.cancel()
	})
}
func (c *NodeShellChannel) Close() error {
	c.releaseContext()
	c.stream.CancelRead(0)
	c.stream.CancelWrite(0)
	return nil
}
