// SPDX-License-Identifier: Apache-2.0

package workload

import (
	"context"
	"errors"
	"io"
	"time"

	"github.com/jay94ks/seafield/internal/containerops"
	"github.com/jay94ks/seafield/internal/engine"
	"github.com/moby/moby/api/pkg/stdcopy"
	"github.com/moby/moby/client"
)

type containerStreamWriter struct {
	kind string
	emit func(containerops.SessionRecord) error
}

func (w containerStreamWriter) Write(p []byte) (int, error) {
	total := 0
	for len(p) > 0 {
		n := min(len(p), containerops.SessionChunkBytes)
		if err := w.emit(containerops.SessionRecord{Kind: w.kind, Data: p[:n]}); err != nil {
			return total, err
		}
		total += n
		p = p[n:]
	}
	return total, nil
}

// StreamContainerExecOutput reuses the pinned SDK demultiplexer and existing
// defensive Docker frame reader. It never turns a partial header into EOF.
func StreamContainerExecOutput(stream io.Reader, tty bool, emit func(containerops.SessionRecord) error) error {
	if stream == nil || emit == nil {
		return containerops.ErrSession
	}
	out := containerStreamWriter{kind: "stdout", emit: emit}
	if tty {
		_, err := io.CopyBuffer(out, stream, make([]byte, containerops.SessionChunkBytes))
		return err
	}
	_, err := stdcopy.StdCopy(out, containerStreamWriter{kind: "stderr", emit: emit}, &probeExecFrames{source: stream})
	return err
}

func (m *Manager) FollowContainerLogs(ctx context.Context, target containerops.Target, q containerops.Query, emit func(containerops.SessionRecord) error) error {
	if q.Validate() != nil || q.Kind != "logs" || q.Until != "" || q.Cursor != "" || !target.Valid() || emit == nil || m == nil || m.driver == nil || m.driver.Engine == nil || m.driver.Engine.Owner != engine.Owner(target.Cluster, target.Owner) {
		return containerops.ErrSession
	}
	current, err := m.ProbeTarget(ctx, target.Instance, target.Generation, target.Revision)
	if err != nil || current.Status.NativeID != target.NativeID || current.Status.StartedAt != target.StartedAt {
		return errors.Join(engine.ErrOwnership, err)
	}
	values, err := m.logRedactionValues(ctx, target)
	if err != nil {
		return err
	}
	defer destroyLogValues(values)
	inspected, err := m.driver.Engine.API.ContainerInspect(ctx, target.NativeID, client.ContainerInspectOptions{})
	if err != nil || inspected.Container.Config == nil || inspected.Container.ID != target.NativeID {
		return errors.Join(engine.ErrOwnership, err)
	}
	tty := inspected.Container.Config.Tty
	meta := containerops.Result{Schema: 1, Kind: "logs", Target: target, ObservedAt: time.Now().UTC(), TTY: tty, LogDriver: current.Status.LogDriver}
	if err = emit(containerops.SessionRecord{Kind: "sample", Sample: &meta}); err != nil {
		return err
	}
	logs, err := m.containerLogs(ctx, target.NativeID, q, tty, true)
	if err != nil {
		return err
	}
	defer logs.Close()
	done := make(chan struct{})
	stop := context.AfterFunc(ctx, func() { _ = logs.Close(); close(done) })
	defer func() {
		if !stop() {
			<-done
		}
	}()
	out, err := containerops.NewRedactor(containerStreamWriter{kind: "stdout", emit: emit}, values)
	if err != nil {
		return err
	}
	defer out.Destroy()
	diagnostic, err := containerops.NewRedactor(containerStreamWriter{kind: "stderr", emit: emit}, values)
	if err != nil {
		return err
	}
	defer diagnostic.Destroy()
	if tty {
		_, err = io.CopyBuffer(out, logs, make([]byte, containerops.SessionChunkBytes))
	} else {
		_, err = stdcopy.StdCopy(out, diagnostic, &probeExecFrames{source: logs})
	}
	if err == nil {
		err = out.Finish()
		if err == nil {
			err = diagnostic.Finish()
		}
	}
	return err
}
