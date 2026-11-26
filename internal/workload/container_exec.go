// SPDX-License-Identifier: Apache-2.0

package workload

import (
	"context"
	"errors"
	"io"
	"slices"
	"sync"
	"time"

	"github.com/jay94ks/mydcd/internal/containerops"
	"github.com/jay94ks/mydcd/internal/engine"
	"github.com/moby/moby/client"
)

// UserExecIO owns only the attached I/O. Close never signals the process or
// kills its container. Durable receipt ownership belongs to the caller's
// existing private node store, separate from lifecycle checker receipts.
type UserExecIO struct {
	attached client.ExecAttachResult
	stop     func() bool
	done     chan struct{}
	once     sync.Once
	stdin    bool
	tty      bool
	execID   string
	api      *client.Client
	check    func(context.Context) error
}

func (s *UserExecIO) Read(p []byte) (int, error) { return s.attached.Reader.Read(p) }
func (s *UserExecIO) Write(p []byte) (int, error) {
	if !s.stdin {
		return 0, io.ErrClosedPipe
	}
	return s.attached.Conn.Write(p)
}
func (s *UserExecIO) CloseWrite() error {
	if !s.stdin {
		return nil
	}
	err := s.attached.CloseWrite()
	if err == nil {
		s.stdin = false
	}
	return err
}
func (s *UserExecIO) Close() error {
	s.once.Do(func() {
		if !s.stop() {
			<-s.done
		}
		s.attached.Close()
	})
	return nil
}
func (s *UserExecIO) Resize(ctx context.Context, rows, cols uint16) error {
	if !s.tty || rows == 0 || cols == 0 {
		return containerops.ErrSession
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if err := s.check(ctx); err != nil {
		return err
	}
	_, err := s.api.ExecResize(ctx, s.execID, client.ExecResizeOptions{Height: uint(rows), Width: uint(cols)})
	return err
}

// StartContainerExec is one-shot. reserve atomically inserts the initial
// receipt in the existing owner store; an existing original returns metadata
// without Create/Attach. save must persist only CanFollow transitions. Neither
// recovery nor status lookup calls this method to resume an old native exec.
func (m *Manager) StartContainerExec(ctx context.Context, intent containerops.SessionIntent, reserve func(containerops.ExecReceipt) (containerops.ExecReceipt, bool, error), save func(containerops.ExecReceipt) error, authorize func(context.Context) error) (*UserExecIO, containerops.ExecReceipt, error) {
	r := containerops.ExecReceipt{Schema: 1, Intent: intent.Digest(), Phase: containerops.ExecCreating}
	if intent.Validate() != nil || intent.Spec.Kind != "exec" || reserve == nil || save == nil || authorize == nil || m == nil || m.driver == nil || m.driver.Engine == nil || m.driver.Engine.Owner != engine.Owner(intent.Target.Cluster, intent.Target.Owner) || ctx == nil {
		return nil, r, containerops.ErrSession
	}
	api, err := m.driver.Engine.StreamingAPI()
	if err != nil {
		return nil, r, err
	}
	check := func(call context.Context) error {
		if err := authorize(call); err != nil {
			return err
		}
		t := intent.Target
		current, err := m.ProbeTarget(call, t.Instance, t.Generation, t.Revision)
		if err != nil || !current.Status.Running || current.Status.NativeID != t.NativeID || current.Status.StartedAt != t.StartedAt {
			return errors.Join(engine.ErrOwnership, err)
		}
		return nil
	}
	if err = check(ctx); err != nil {
		return nil, r, err
	}
	r, fresh, err := reserve(r)
	if err != nil || r.Validate() != nil || r.Intent != intent.Digest() {
		return nil, r, errors.Join(containerops.ErrSession, err)
	}
	if !fresh {
		return nil, r, nil
	}
	if r.Phase != containerops.ExecCreating {
		return nil, r, containerops.ErrSession
	}
	q := intent.Spec.Exec
	size := client.ConsoleSize{Height: uint(q.Rows), Width: uint(q.Cols)}
	createCtx, createDone := context.WithTimeout(ctx, 5*time.Second)
	created, err := m.driver.Engine.API.ExecCreate(createCtx, intent.Target.NativeID, client.ExecCreateOptions{Cmd: slices.Clone(q.Argv), TTY: q.TTY, ConsoleSize: size, AttachStdin: q.Stdin, AttachStdout: true, AttachStderr: true})
	createDone()
	if err != nil {
		return nil, r, err // Config creation may be unknown; no Attach was sent.
	}
	next := r
	next.ExecID, next.Phase = created.ID, containerops.ExecCreated
	if !next.CanFollow(r) {
		return nil, r, containerops.ErrSession
	}
	if err = save(next); err != nil {
		return nil, r, err
	}
	r = next
	if err = check(ctx); err != nil {
		return nil, r, err
	}
	next.Phase = containerops.ExecStartSent
	if err = save(next); err != nil {
		return nil, r, err
	}
	r = next
	attachCtx, attachDone := context.WithTimeout(ctx, 5*time.Second)
	attached, err := api.ExecAttach(attachCtx, r.ExecID, client.ExecAttachOptions{TTY: q.TTY, ConsoleSize: size})
	// The pinned SDK detaches a successful hijack from its handshake context.
	// The live I/O lifetime below remains bound to the parent session context.
	attachDone()
	if err != nil {
		return nil, r, err // Do not Attach again after an uncertain response.
	}
	next.Phase = containerops.ExecStarted
	if err = save(next); err != nil {
		attached.Close()
		return nil, r, err
	}
	r = next
	stream := &UserExecIO{attached: attached, stdin: q.Stdin, tty: q.TTY, execID: r.ExecID, api: api, check: check, done: make(chan struct{})}
	stream.stop = context.AfterFunc(ctx, func() { attached.Close(); close(stream.done) })
	return stream, r, nil
}

// InspectContainerExec does not require a still-current Task/Binding: it reads
// the retained original ExecID even after I/O ended. The caller checks current
// user authority on that original tenant/app; an absent native stays unknown.
func (m *Manager) InspectContainerExec(ctx context.Context, target containerops.Target, receipt containerops.ExecReceipt, authorize func(context.Context) error) (containerops.ExecReceipt, *bool, error) {
	if ctx == nil || !target.Valid() || target.NativeID == "" || receipt.Validate() != nil || authorize == nil || m == nil || m.driver == nil || m.driver.Engine == nil || m.driver.Engine.Owner != engine.Owner(target.Cluster, target.Owner) {
		return receipt, nil, containerops.ErrSession
	}
	if err := authorize(ctx); err != nil {
		return receipt, nil, err
	}
	if receipt.ExecID == "" {
		return receipt, nil, nil
	}
	result, knownExit, err := m.driver.Engine.InspectExec(ctx, receipt.ExecID)
	if err != nil || result.ContainerID != target.NativeID || result.ID != receipt.ExecID {
		return receipt, nil, errors.Join(engine.ErrOwnership, err)
	}
	exit := -1
	if knownExit {
		exit = result.ExitCode
	}
	next, err := receipt.Observe(result.Running, exit)
	if err != nil || !next.CanFollow(receipt) {
		return receipt, nil, errors.Join(containerops.ErrSession, err)
	}
	running := result.Running
	return next, &running, nil
}
