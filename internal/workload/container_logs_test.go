// SPDX-License-Identifier: Apache-2.0

package workload

import (
	"context"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/jay94ks/seafield/internal/containerops"
	"github.com/jay94ks/seafield/internal/logstore"
)

type fakeLogs struct {
	got logstore.ReadOptions
	id  string
	err error
}

func (f *fakeLogs) Stream(_ context.Context, id string, o logstore.ReadOptions) (io.ReadCloser, error) {
	f.id, f.got = id, o
	if f.err != nil {
		return nil, f.err
	}
	return io.NopCloser(strings.NewReader("line")), nil
}

// Container logs come from this server's log store with the query's
// window, and a container with no stored lines reads empty (R18 E6).
func TestContainerLogsReadTheStore(t *testing.T) {
	m := &Manager{}
	if _, err := m.containerLogs(t.Context(), "abc", containerops.Query{}, false, false); err == nil {
		t.Fatal("read without a log store")
	}
	f := &fakeLogs{}
	m.SetLogs(f)
	q := containerops.Query{Kind: "logs", Tail: 10, Stdout: true, Timestamps: true, Since: "2026-11-27T10:00:00Z", Until: "2026-11-27T11:00:00.5Z"}
	rc, err := m.containerLogs(t.Context(), "abc", q, true, true)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := io.ReadAll(rc)
	want := logstore.ReadOptions{Tail: 10, Stdout: true, Timestamps: true, TTY: true, Follow: true, Since: time.Date(2026, 11, 27, 10, 0, 0, 0, time.UTC), Until: time.Date(2026, 11, 27, 11, 0, 0, 5e8, time.UTC)}
	if string(raw) != "line" || f.id != "abc" || f.got != want {
		t.Fatalf("store read %q %s %+v", raw, f.id, f.got)
	}
	f.err = logstore.ErrNotFound
	rc, err = m.containerLogs(t.Context(), "abc", containerops.Query{Kind: "logs", Tail: 1, Stdout: true}, false, false)
	if err != nil {
		t.Fatal(err)
	}
	if raw, _ = io.ReadAll(rc); len(raw) != 0 {
		t.Fatal("missing log was not empty")
	}
}

type laterLogs struct{ calls int }

func (l *laterLogs) Stream(context.Context, string, logstore.ReadOptions) (io.ReadCloser, error) {
	l.calls++
	if l.calls < 3 {
		return nil, logstore.ErrNotFound
	}
	return io.NopCloser(strings.NewReader("first")), nil
}

// Following a container that has written nothing yet waits for its first
// lines instead of ending at once, and ends when the caller stops.
func TestContainerLogsFollowWaitsForTheFirstLine(t *testing.T) {
	old := logWaitInterval
	logWaitInterval = time.Millisecond
	t.Cleanup(func() { logWaitInterval = old })
	m := &Manager{}
	l := &laterLogs{}
	m.SetLogs(l)
	rc, err := m.containerLogs(t.Context(), "abc", containerops.Query{Kind: "logs", Stdout: true}, false, true)
	if err != nil {
		t.Fatal(err)
	}
	if raw, _ := io.ReadAll(rc); string(raw) != "first" || l.calls != 3 {
		t.Fatalf("follow read %q after %d opens", raw, l.calls)
	}
	ctx, cancel := context.WithCancel(t.Context())
	m.SetLogs(&fakeLogs{err: logstore.ErrNotFound})
	rc, err = m.containerLogs(ctx, "abc", containerops.Query{Kind: "logs", Stdout: true}, false, true)
	if err != nil {
		t.Fatal(err)
	}
	cancel()
	if raw, err := io.ReadAll(rc); err != nil || len(raw) != 0 {
		t.Fatalf("cancelled follow read %q %v", raw, err)
	}
	_ = rc.Close()
}
