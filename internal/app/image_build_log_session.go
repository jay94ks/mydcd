// SPDX-License-Identifier: Apache-2.0

package app

import (
	"context"
	"errors"
	"sync"

	"github.com/jay94ks/mydcd/internal/imagebuild"
)

// This finite session joins Secret staging, filtered SDK output and the same
// node log store. The worker opens it after context copy and before Start, and
// flushes it during normal progress polling. It is not a background log daemon.
type imageBuildLogSession struct {
	stream *imagebuild.NativeLogs
	writer *imagebuild.LogWriter
	finish func()
	gap    func() error
}

func (r *Runtime) prepareImageBuildLogs(ctx context.Context, native *imagebuild.NativeJobs, spec imagebuild.JobSpec) (*imageBuildLogSession, error) {
	if native == nil {
		return nil, imagebuild.ErrInvalid
	}
	ctx, cancel := context.WithCancel(ctx)
	stop := context.AfterFunc(r.ctx, cancel)
	finish := sync.OnceFunc(func() { stop(); cancel() })
	writer, err := native.OpenLogWriter(ctx, spec)
	if err != nil {
		finish()
		return nil, err
	}
	filter, err := r.stageImageBuildSecrets(ctx, spec, native, writer)
	if err != nil {
		finish()
		return nil, errors.Join(err, writer.Close())
	}
	stream, err := native.AttachLogs(ctx, spec, filter)
	filter.Destroy() // attach forks own their transient matcher bytes
	if err != nil {
		finish()
		return nil, errors.Join(err, writer.Close())
	}
	return &imageBuildLogSession{stream: stream, writer: writer, finish: finish, gap: func() error { return native.MarkLogGap(spec) }}, nil
}
func (l *imageBuildLogSession) Flush() error { return l.writer.Flush() }
func (l *imageBuildLogSession) Wait() error {
	streamErr := l.stream.Wait()
	if streamErr != nil {
		streamErr = errors.Join(streamErr, l.gap())
	}
	l.finish()
	return errors.Join(streamErr, l.writer.Close())
}
func (l *imageBuildLogSession) Close() error {
	if l == nil {
		return nil
	}
	streamErr := l.stream.Close()
	if streamErr != nil {
		streamErr = errors.Join(streamErr, l.gap())
	}
	l.finish()
	return errors.Join(streamErr, l.writer.Close())
}

func (l *imageBuildLogSession) Drain(ctx context.Context) error {
	select {
	case <-l.stream.Done():
		return l.Wait()
	case <-ctx.Done():
		return l.Close()
	}
}
