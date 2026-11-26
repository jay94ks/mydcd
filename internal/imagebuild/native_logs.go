// SPDX-License-Identifier: Apache-2.0

package imagebuild

import (
	"context"
	"errors"
	"sync"

	"github.com/jay94ks/mydcd/internal/containerops"
	"github.com/jay94ks/mydcd/internal/engine"
	"github.com/moby/moby/api/pkg/stdcopy"
	"github.com/moby/moby/client"
)

// NativeLogs owns only a live SDK attach stream, never raw Docker history.
// Both Wait and Close join its reader, filtering and native descriptors before
// workspace/root cleanup. EOF is a log boundary, not proof of native exit.
type NativeLogs struct {
	done   chan struct{}
	cancel context.CancelFunc
	err    error
}

func (l *NativeLogs) Wait() error           { <-l.done; return l.err }
func (l *NativeLogs) Done() <-chan struct{} { return l.done }
func (l *NativeLogs) Close() error {
	if l == nil {
		return nil
	}
	l.cancel()
	return l.Wait()
}

// AttachLogs is called after Create/StageControls and before Start. The caller
// supplies the exact build Secret filter and a bounded redacted-log writer.
// Restart recovery may attach to that same running container with current
// authorization/filters, but cannot replay missing history or claim no gap.
func (n *NativeJobs) AttachLogs(ctx context.Context, spec JobSpec, filter *containerops.Redactor) (*NativeLogs, error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	r, err := n.load(spec)
	if err != nil {
		return nil, err
	}
	if _, err := n.current(ctx, &r, false); err != nil {
		return nil, err
	}
	job := spec.Digest()
	if r.NativeID == "" || !r.ControlsDone || r.Cancel || r.Removed || r.Completion != nil {
		return nil, ErrConflict
	}
	if n.logging[job] {
		return nil, ErrUsed
	}
	stdout, err := filter.Fork()
	if err != nil {
		return nil, err
	}
	stderr, err := filter.Fork()
	if err != nil {
		stdout.Destroy()
		return nil, err
	}
	failFilters := func() { stdout.Destroy(); stderr.Destroy() }
	files, err := n.openWorkspace(r)
	if err != nil {
		failFilters()
		return nil, err
	}
	n.readers[job]++
	release := func(closeErr error) {
		if closeErr == nil {
			n.readers[job]--
			if n.readers[job] == 0 {
				delete(n.readers, job)
			}
		}
	}
	api, err := n.docker.BindStreamingClient(files.Sources())
	if err != nil {
		failFilters()
		closeErr := files.Close()
		release(closeErr)
		return nil, errors.Join(err, closeErr)
	}
	fail := func(cause error) (*NativeLogs, error) {
		failFilters()
		closeErr := errors.Join(api.Close(), files.Close())
		release(closeErr)
		if closeErr != nil {
			cause = errors.Join(cause, ErrStorage)
		}
		return nil, cause
	}
	plan, err := PlanNative(spec, n.docker.Owner)
	if err != nil {
		return fail(err)
	}
	got, err := n.docker.API.ContainerInspect(ctx, r.NativeID, client.ContainerInspectOptions{})
	if err != nil {
		return fail(nativeFailure(ctx))
	}
	if !matchNativeContainer(got.Container, r, plan) {
		return fail(engine.ErrOwnership)
	}
	if _, err := n.current(ctx, &r, false); err != nil {
		return fail(err)
	}
	streamCtx, cancel := context.WithCancel(ctx)
	attached, err := api.ContainerAttach(streamCtx, r.NativeID, client.ContainerAttachOptions{Stream: true, Stdout: true, Stderr: true})
	if err != nil {
		cancel()
		return fail(nativeFailure(ctx))
	}
	closeConnection := sync.OnceFunc(attached.Close)
	stop := context.AfterFunc(streamCtx, closeConnection)
	logs := &NativeLogs{done: make(chan struct{}), cancel: cancel}
	n.logging[job] = true
	go func() {
		defer close(logs.done)
		// SDK demultiplexing serializes writes, while separate filters retain
		// each stream's private prefix across interleaved frames/chunks.
		_, copyErr := stdcopy.StdCopy(stdout, stderr, attached.Reader)
		if copyErr == nil && streamCtx.Err() == nil {
			copyErr = stdout.Finish()
			if copyErr == nil {
				copyErr = stderr.Finish()
			}
		}
		stdout.Destroy()
		stderr.Destroy()
		stop()
		closeConnection()
		closeErr := errors.Join(api.Close(), files.Close())
		if copyErr != nil || streamCtx.Err() != nil {
			logs.err = nativeFailure(streamCtx) // no raw Engine/system-error body
		}
		if closeErr != nil {
			logs.err = errors.Join(logs.err, ErrStorage)
		}
		cancel()
		n.mu.Lock()
		defer n.mu.Unlock()
		delete(n.logging, job)
		release(closeErr)
	}()
	return logs, nil
}
