// SPDX-License-Identifier: Apache-2.0

package imagebuild

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"strings"
	"sync"
	"testing"

	"github.com/jay94ks/seafield/internal/containerops"
	"github.com/moby/moby/api/pkg/stdcopy"
	"github.com/moby/moby/api/types/container"
)

func nativeLogFrame(kind stdcopy.StdType, payload string) []byte {
	frame := make([]byte, 8+len(payload))
	frame[0] = byte(kind)
	binary.BigEndian.PutUint32(frame[4:], uint32(len(payload)))
	copy(frame[8:], payload)
	return frame
}

func TestNativeLogsRedactSeparateStreamsAndJoinBeforeWorkspaceClosure(t *testing.T) {
	f := newNativeFixture(t, true)
	ctx := f.ctx()
	f.prepare(ctx)
	var frames, output bytes.Buffer
	frames.Write(nativeLogFrame(stdcopy.Stdout, "token-"))
	frames.Write(nativeLogFrame(stdcopy.Stderr, "diagnostic\n"))
	frames.Write(nativeLogFrame(stdcopy.Stdout, "value\n"))
	release := make(chan struct{})
	finish := sync.OnceFunc(func() { close(release) })
	defer finish()
	f.edit(func() { f.logFrames, f.logRelease = frames.Bytes(), release })
	filter, err := containerops.NewRedactor(&output, []containerops.RedactionValue{{Reference: "tenant/key", Value: []byte("token-value")}})
	if err != nil {
		t.Fatal(err)
	}
	defer filter.Destroy()
	logs, err := f.jobs.AttachLogs(ctx, f.spec, filter)
	if err != nil {
		t.Fatal(err)
	}
	defer logs.Close()
	filter.Destroy() // stream forks own independent copies of private patterns
	if _, err := f.jobs.AttachLogs(ctx, f.spec, nil); !errors.Is(err, ErrUsed) {
		t.Fatal("duplicate attach allowed", err)
	}
	if err := f.jobs.Start(ctx, f.spec); err != nil {
		t.Fatal(err)
	}
	f.edit(func() {
		f.state = container.State{Status: container.StateExited, ExitCode: 1, StartedAt: "2026-11-22T00:00:01Z", FinishedAt: "2026-11-22T00:00:02Z"}
	})
	if err := f.jobs.ObserveExit(ctx, f.spec, false); err != nil {
		t.Fatal(err)
	}
	if err := f.jobs.Remove(ctx, f.spec); err != nil {
		t.Fatal(err)
	}
	if _, err := f.jobs.FinishWorkspace(ctx, f.spec); !errors.Is(err, ErrUsed) {
		t.Fatal("unjoined stream allowed workspace deletion", err)
	}
	finish()
	if err := logs.Wait(); err != nil {
		t.Fatal(err)
	}
	if got := output.String(); strings.Contains(got, "token-") || strings.Contains(got, "value") || !strings.Contains(got, "«가림: tenant/key»") || !strings.Contains(got, "diagnostic") {
		t.Fatal("interleaved stream redaction", got)
	}
	if _, err := f.jobs.FinishWorkspace(ctx, f.spec); err != nil {
		t.Fatal("joined stream retained workspace", err)
	}
}

func TestNativeLogsCancellationJoinsReaderAndDoesNotExposeDaemonError(t *testing.T) {
	for _, interrupted := range []bool{false, true} {
		t.Run(map[bool]string{false: "daemon-error", true: "cancel"}[interrupted], func(t *testing.T) {
			f := newNativeFixture(t, false)
			ctx, cancel := context.WithCancel(f.ctx())
			defer cancel()
			f.prepare(ctx)
			var frames, output bytes.Buffer
			frames.Write(nativeLogFrame(stdcopy.Systemerr, "private daemon failure body"))
			release := make(chan struct{})
			defer close(release)
			f.edit(func() {
				f.logFrames = frames.Bytes()
				if interrupted {
					f.logRelease = release
				}
			})
			filter, err := containerops.NewRedactor(&output, nil)
			if err != nil {
				t.Fatal(err)
			}
			defer filter.Destroy()
			logs, err := f.jobs.AttachLogs(ctx, f.spec, filter)
			if err != nil {
				t.Fatal(err)
			}
			defer logs.Close()
			if interrupted {
				cancel()
			}
			err = logs.Wait()
			if err == nil || strings.Contains(err.Error(), "private") || output.Len() != 0 {
				t.Fatal("raw daemon failure leaked", output.String(), err)
			}
			r, err := f.jobs.Record(f.spec)
			if err != nil || r.Waited || r.Exited || r.Removed {
				t.Fatal("attach EOF/failure fabricated native closure", r, err)
			}
			f.jobs.mu.Lock()
			readers, logging := f.jobs.readers[f.spec.Digest()], f.jobs.logging[f.spec.Digest()]
			f.jobs.mu.Unlock()
			if readers != 0 || logging {
				t.Fatal("reader not joined", readers, logging)
			}
		})
	}
}
