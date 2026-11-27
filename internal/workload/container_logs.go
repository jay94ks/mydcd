// SPDX-License-Identifier: Apache-2.0

package workload

import (
	"context"
	"errors"
	"io"
	"time"

	"github.com/jay94ks/seafield/internal/containerops"
	"github.com/jay94ks/seafield/internal/logstore"
)

// LogReader is this server's container log store (sfcd's logstore, R18 E6):
// the engine hands log lines to sfcd, so logs are read from the store, never
// from the engine's container logs API.
type LogReader interface {
	Stream(ctx context.Context, id string, o logstore.ReadOptions) (io.ReadCloser, error)
}

// SetLogs gives the manager this server's log store.
func (m *Manager) SetLogs(l LogReader) { m.logs = l }

// containerLogs streams a container's stored log for q in the Engine API's
// container logs encoding. A container with no stored lines yet reads empty.
func (m *Manager) containerLogs(ctx context.Context, nativeID string, q containerops.Query, tty, follow bool) (io.ReadCloser, error) {
	if m.logs == nil {
		return nil, errors.New("workload: no container log store")
	}
	o := logstore.ReadOptions{Tail: q.Tail, Stdout: q.Stdout, Stderr: q.Stderr, Timestamps: q.Timestamps, TTY: tty, Follow: follow}
	var err error
	if q.Since != "" {
		if o.Since, err = time.Parse(time.RFC3339Nano, q.Since); err != nil {
			return nil, containerops.ErrQuery
		}
	}
	if q.Until != "" {
		if o.Until, err = time.Parse(time.RFC3339Nano, q.Until); err != nil {
			return nil, containerops.ErrQuery
		}
	}
	rc, err := m.logs.Stream(ctx, nativeID, o)
	if errors.Is(err, logstore.ErrNotFound) {
		if follow {
			return &pendingLog{ctx: ctx, open: func() (io.ReadCloser, error) { return m.logs.Stream(ctx, nativeID, o) }}, nil
		}
		return io.NopCloser(eofReader{}), nil
	}
	return rc, err
}

// logWaitInterval is how often a follow of a container with no stored lines
// yet checks whether its log has started.
var logWaitInterval = 500 * time.Millisecond

// pendingLog is a follow of a container whose log has no lines yet: the
// first Read waits until the log exists, then streams it, so follow does not
// end at once for a container that has not written anything. It ends when ctx
// ends.
type pendingLog struct {
	ctx  context.Context
	open func() (io.ReadCloser, error)
	rc   io.ReadCloser
}

func (p *pendingLog) Read(b []byte) (int, error) {
	for p.rc == nil {
		rc, err := p.open()
		if err == nil {
			p.rc = rc
			break
		}
		if !errors.Is(err, logstore.ErrNotFound) {
			return 0, err
		}
		t := time.NewTimer(logWaitInterval)
		select {
		case <-p.ctx.Done():
			t.Stop()
			return 0, io.EOF
		case <-t.C:
		}
	}
	return p.rc.Read(b)
}

func (p *pendingLog) Close() error {
	if p.rc != nil {
		return p.rc.Close()
	}
	return nil
}

type eofReader struct{}

func (eofReader) Read([]byte) (int, error) { return 0, io.EOF }
