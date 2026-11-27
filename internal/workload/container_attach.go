// SPDX-License-Identifier: Apache-2.0

package workload

import (
	"context"
	"errors"
	"github.com/jay94ks/seafield/internal/containerops"
	"github.com/jay94ks/seafield/internal/engine"
	"github.com/moby/moby/client"
	"io"
	"sync"
	"time"
)

// ContainerAttachIO is an I/O connection to the original process. Reconnection
// never creates an exec, restarts the process, or replaces its writable layer.
type ContainerAttachIO struct {
	attached   client.ContainerAttachResult
	api        *client.Client
	native     string
	stdin, tty bool
	check      func(context.Context) error
	stop       func() bool
	done       chan struct{}
	once       sync.Once
}

func (s *ContainerAttachIO) Read(p []byte) (int, error) { return s.attached.Reader.Read(p) }
func (s *ContainerAttachIO) Write(p []byte) (int, error) {
	if !s.stdin {
		return 0, io.ErrClosedPipe
	}
	return s.attached.Conn.Write(p)
}
func (s *ContainerAttachIO) CloseWrite() error {
	if !s.stdin {
		return nil
	}
	return s.attached.CloseWrite()
}
func (s *ContainerAttachIO) Close() error {
	s.once.Do(func() {
		if !s.stop() {
			<-s.done
		}
		s.attached.Close()
	})
	return nil
}
func (s *ContainerAttachIO) Resize(ctx context.Context, rows, cols uint16) error {
	if !s.tty || rows == 0 || cols == 0 {
		return containerops.ErrSession
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if err := s.check(ctx); err != nil {
		return err
	}
	_, err := s.api.ContainerResize(ctx, s.native, client.ContainerResizeOptions{Height: uint(rows), Width: uint(cols)})
	return err
}
func (m *Manager) AttachContainer(ctx context.Context, intent containerops.SessionIntent, authorize func(context.Context) error) (*ContainerAttachIO, error) {
	if ctx == nil || intent.Validate() != nil || intent.Spec.Kind != "attach" || intent.Target.Standalone == "" || authorize == nil || m == nil || m.driver == nil || m.driver.Engine == nil || m.driver.Engine.Owner != engine.Owner(intent.Target.Cluster, intent.Target.Owner) {
		return nil, containerops.ErrSession
	}
	check := func(call context.Context) error {
		if err := authorize(call); err != nil {
			return err
		}
		t := intent.Target
		got, err := m.ProbeTarget(call, t.Instance, t.Generation, t.Revision)
		if err != nil || !got.Status.Running || got.Status.NativeID != t.NativeID || got.Status.StartedAt != t.StartedAt {
			return errors.Join(engine.ErrOwnership, err)
		}
		return nil
	}
	if err := check(ctx); err != nil {
		return nil, err
	}
	api, err := m.driver.Engine.StreamingAPI()
	if err != nil {
		return nil, err
	}
	inspect, err := api.ContainerInspect(ctx, intent.Target.NativeID, client.ContainerInspectOptions{})
	if err != nil || inspect.Container.Config == nil {
		return nil, errors.Join(engine.ErrOwnership, err)
	}
	q := intent.Spec.Exec
	if q.TTY != inspect.Container.Config.Tty || q.Stdin && !inspect.Container.Config.OpenStdin {
		return nil, containerops.ErrSession
	}
	call, finish := context.WithTimeout(ctx, 5*time.Second)
	attached, err := api.ContainerAttach(call, intent.Target.NativeID, client.ContainerAttachOptions{Stream: true, Stdin: q.Stdin, Stdout: true, Stderr: true})
	finish()
	if err != nil {
		return nil, err
	}
	stream := &ContainerAttachIO{attached: attached, api: api, native: intent.Target.NativeID, stdin: q.Stdin, tty: q.TTY, check: check, done: make(chan struct{})}
	stream.stop = context.AfterFunc(ctx, func() { attached.Close(); close(stream.done) })
	if q.TTY {
		if err = stream.Resize(ctx, q.Rows, q.Cols); err != nil {
			stream.Close()
			return nil, err
		}
	}
	return stream, nil
}
