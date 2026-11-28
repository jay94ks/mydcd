// SPDX-License-Identifier: Apache-2.0

package sfev

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jay94ks/seafield/internal/peercred"
	client "github.com/jay94ks/seafield/internal/sfev/sfevtest"
	"golang.org/x/sys/unix"
)

type values struct {
	mu   sync.Mutex
	snap Snapshot
	err  error
	n    int
	// during runs inside fetch, outside the lock, when set.
	during func()
}

func (v *values) set(snap Snapshot, err error) {
	v.mu.Lock()
	v.snap, v.err = snap, err
	v.mu.Unlock()
}

func (v *values) fetch(context.Context) (Snapshot, error) {
	v.mu.Lock()
	during := v.during
	v.during = nil
	v.n++
	snap, err := v.snap, v.err
	v.mu.Unlock()
	if during != nil {
		during()
	}
	return snap, err
}

func (v *values) count() int {
	v.mu.Lock()
	defer v.mu.Unlock()
	return v.n
}

func skipWithoutPeerPidfd(t *testing.T) {
	t.Helper()
	path := t.TempDir() + "/probe.sock"
	l, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	c, err := net.Dial("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	s, err := l.AcceptUnix()
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	p, err := peercred.Peer(s)
	if err != nil {
		t.Skipf("kernel cannot name the peer by pidfd: %v", err)
	}
	_ = p.Close()
}

func open(t *testing.T, mutate func(*Config)) (*Endpoint, *values) {
	t.Helper()
	skipWithoutPeerPidfd(t)
	fd, err := unix.PidfdOpen(os.Getpid(), 0)
	if err != nil {
		t.Skipf("pidfd: %v", err)
	}
	anchor := peercred.Process{PID: os.Getpid(), FD: fd}
	defer anchor.Close()
	v := &values{snap: Snapshot{Revision: "r1", Values: map[string]string{"db": "one", "token": "t1"}}}
	cfg := Config{Name: "test", Dir: t.TempDir(), Anchor: anchor, UID: uint32(os.Getuid()), GID: uint32(os.Getgid()), Fetch: v.fetch, Logf: t.Logf}
	if mutate != nil {
		mutate(&cfg)
	}
	e, err := Open(cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = e.Close() })
	info, err := os.Stat(e.Path())
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("socket mode = %v %v", info, err)
	}
	return e, v
}

func dial(t *testing.T, e *Endpoint) *client.Client {
	t.Helper()
	c, err := client.Dial(e.Path())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c
}

func ctx(t *testing.T) context.Context {
	t.Helper()
	c, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	t.Cleanup(cancel)
	return c
}

func TestSingleRequests(t *testing.T) {
	e, v := open(t, nil)
	c := dial(t, e)
	all, err := c.Secrets(ctx(t))
	if err != nil || all.Revision != "r1" || all.Values["db"] != "one" || len(all.Values) != 2 {
		t.Fatalf("values = %+v %v", all, err)
	}
	// Same connection, next stream.
	value, revision, err := c.Secret(ctx(t), "token")
	if err != nil || value != "t1" || revision != "r1" {
		t.Fatalf("key = %q %q %v", value, revision, err)
	}
	if _, _, err = c.Secret(ctx(t), "missing"); !errors.Is(err, client.ErrNotFound) {
		t.Fatalf("missing key = %v", err)
	}
	if v.count() != 3 {
		t.Fatalf("fetches = %d", v.count())
	}
}

func TestHTTP1IsRefused(t *testing.T) {
	e, v := open(t, nil)
	conn, err := net.Dial("unix", e.Path())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	_, _ = fmt.Fprintf(conn, "GET /v1/secrets HTTP/1.1\r\nHost: x\r\n\r\n")
	line, _ := bufio.NewReader(conn).ReadString('\n')
	if strings.HasPrefix(line, "HTTP/1.1 200") || strings.Contains(line, "one") {
		t.Fatalf("HTTP/1.1 got an answer: %q", line)
	}
	if v.count() != 0 {
		t.Fatal("values were read for an HTTP/1.1 request")
	}
}

func TestOneConnectionPerContainer(t *testing.T) {
	e, _ := open(t, nil)
	first := dial(t, e)
	if _, err := first.Secrets(ctx(t)); err != nil {
		t.Fatal(err) // the slot is now held
	}
	second := dial(t, e)
	if _, err := second.Secrets(ctx(t)); !errors.Is(err, client.ErrBusy) {
		t.Fatalf("second connection = %v", err)
	}
	// The first one is kept.
	if _, _, err := first.Secret(ctx(t), "db"); err != nil {
		t.Fatalf("first after refusal = %v", err)
	}
	// Once it closes, a new connection takes the slot.
	_ = first.Close()
	deadline := time.Now().Add(5 * time.Second)
	for {
		third := dial(t, e)
		_, err := third.Secrets(ctx(t))
		if err == nil {
			return
		}
		_ = third.Close()
		if time.Now().After(deadline) {
			t.Fatalf("slot never freed: %v", err)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func TestWrongUserGetsNoAnswer(t *testing.T) {
	e, v := open(t, func(c *Config) { c.UID++ })
	c := dial(t, e)
	if _, err := c.Secrets(ctx(t)); err == nil || errors.Is(err, client.ErrBusy) {
		t.Fatalf("refused peer = %v", err)
	}
	if v.count() != 0 {
		t.Fatal("values were read for a refused peer")
	}
}

func TestFetchErrorsMapToStatus(t *testing.T) {
	e, v := open(t, nil)
	c := dial(t, e)
	for _, tc := range []struct {
		err  error
		snap Snapshot
		want error
	}{
		{err: ErrDenied, want: client.ErrDenied},
		{err: errors.New("quorum unreachable"), want: client.ErrUnavailable},
		{snap: Snapshot{Revision: "big", Values: map[string]string{"k": strings.Repeat("x", MaxValues)}}, want: client.ErrTooLarge},
	} {
		v.set(tc.snap, tc.err)
		if _, err := c.Secrets(ctx(t)); !errors.Is(err, tc.want) {
			t.Fatalf("%v → %v, want %v", tc.err, err, tc.want)
		}
	}
}

func watch(t *testing.T, c *client.Client) *client.Watch {
	t.Helper()
	w, err := c.Watch(ctx(t))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = w.Close() })
	return w
}

func next(t *testing.T, w *client.Watch) client.Event {
	t.Helper()
	ev, err := w.Next()
	if err != nil {
		t.Fatal(err)
	}
	return ev
}

func TestWatchStreamsChangesAndRevocation(t *testing.T) {
	e, v := open(t, nil)
	c := dial(t, e)
	w := watch(t, c)
	if ev := next(t, w); ev.Type != "snapshot" || ev.Revision != "r1" || ev.Values["token"] != "t1" {
		t.Fatalf("first event = %+v", ev)
	}
	// Single reads still work beside the open watch (another stream).
	if _, _, err := c.Secret(ctx(t), "db"); err != nil {
		t.Fatalf("read beside watch: %v", err)
	}
	// A second watch on the same connection is refused.
	if _, err := c.Watch(ctx(t)); !errors.Is(err, client.ErrBusy) {
		t.Fatalf("second watch = %v", err)
	}
	reads := v.count()
	// Same revision: nothing is sent.
	e.Publish(Event{Kind: Changed})
	v.set(Snapshot{Revision: "r2", Values: map[string]string{"db": "one", "token": "t2", "new": "n"}}, nil)
	e.Publish(Event{Kind: Changed})
	ev := next(t, w)
	if ev.Type != "changed" || ev.Revision != "r2" || len(ev.Values) != 2 || ev.Values["token"] != "t2" || ev.Values["new"] != "n" || len(ev.Removed) != 0 {
		t.Fatalf("changed = %+v", ev)
	}
	if v.count() <= reads {
		t.Fatal("changed did not fetch")
	}
	v.set(Snapshot{Revision: "r3", Values: map[string]string{"db": "one"}}, nil)
	e.Publish(Event{Kind: Changed})
	if ev = next(t, w); ev.Type != "changed" || len(ev.Values) != 0 || strings.Join(ev.Removed, ",") != "new,token" {
		t.Fatalf("removal = %+v", ev)
	}
	reads = v.count()
	e.Publish(Event{Kind: Revoked, Reason: "approval withdrawn"})
	if ev = next(t, w); ev.Type != "revoked" || ev.Reason != "approval withdrawn" {
		t.Fatalf("revoked = %+v", ev)
	}
	if _, err := w.Next(); err == nil {
		t.Fatal("stream continued after revoked")
	}
	if v.count() != reads {
		t.Fatal("revocation fetched values")
	}
}

func TestWatchEndsWhenValuesAreTooLarge(t *testing.T) {
	e, v := open(t, nil)
	w := watch(t, dial(t, e))
	next(t, w)
	// A transient error keeps the stream.
	v.set(Snapshot{}, errors.New("holder not reachable"))
	e.Publish(Event{Kind: Changed})
	v.set(Snapshot{Revision: "big", Values: map[string]string{"k": strings.Repeat("x", MaxValues)}}, nil)
	e.Publish(Event{Kind: Changed})
	if ev := next(t, w); ev.Type != "revoked" || ev.Reason != "413" {
		t.Fatalf("too large = %+v", ev)
	}
}

func TestChangedDuringFirstSnapshotIsNotLost(t *testing.T) {
	e, v := open(t, nil)
	// While the watch reads its snapshot (r1), a new revision commits and
	// its Changed arrives before the snapshot is sent.
	v.mu.Lock()
	v.during = func() {
		v.set(Snapshot{Revision: "r2", Values: map[string]string{"db": "two", "token": "t1"}}, nil)
		e.Publish(Event{Kind: Changed})
	}
	v.mu.Unlock()
	w := watch(t, dial(t, e))
	if ev := next(t, w); ev.Type != "snapshot" || ev.Revision != "r1" {
		t.Fatalf("snapshot = %+v", ev)
	}
	if ev := next(t, w); ev.Type != "changed" || ev.Revision != "r2" || ev.Values["db"] != "two" || len(ev.Values) != 1 {
		t.Fatalf("changed during snapshot = %+v", ev)
	}
}

func TestCloseSendsClosing(t *testing.T) {
	e, _ := open(t, nil)
	w := watch(t, dial(t, e))
	next(t, w)
	done := make(chan error, 1)
	go func() { done <- e.Close() }()
	if ev := next(t, w); ev.Type != "closing" {
		t.Fatalf("close = %+v", ev)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(e.Path()); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("socket left behind: %v", err)
	}
}
