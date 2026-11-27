// SPDX-License-Identifier: Apache-2.0

package logstore

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"
)

const cid = "0123456789abcdef0123"

func recs(from, to uint64, size int) []Record {
	var out []Record
	base := time.Date(2026, 11, 27, 0, 0, 0, 0, time.UTC)
	for s := from; s <= to; s++ {
		out = append(out, Record{Seq: s, Time: base.Add(time.Duration(s) * time.Second), Stderr: s%5 == 0, Data: bytes.Repeat([]byte{'a' + byte(s%26)}, size)})
	}
	return out
}

func seqs(t *testing.T, s *Store, after uint64) []uint64 {
	t.Helper()
	var out []uint64
	if _, err := s.Read(cid, after, func(r Record) bool { out = append(out, r.Seq); return true }); err != nil {
		t.Fatal(err)
	}
	return out
}

func TestAppendReadSkipDuplicates(t *testing.T) {
	s, _ := Open(t.TempDir())
	if _, err := s.Read(cid, 0, func(Record) bool { return true }); !errors.Is(err, ErrNotFound) {
		t.Fatalf("empty store read: %v", err)
	}
	if last, err := s.Append(cid, Meta{App: "web"}, recs(1, 10, 10)); err != nil || last != 10 {
		t.Fatal(last, err)
	}
	if last, _ := s.Append(cid, Meta{}, recs(5, 12, 10)); last != 12 {
		t.Fatal(last)
	}
	got := seqs(t, s, 3)
	if len(got) != 9 || got[0] != 4 || got[8] != 12 {
		t.Fatalf("%v", got)
	}
	in, _ := s.Info(cid)
	if in.First != 1 || in.Last != 12 || in.App != "web" || in.Dropped != 0 {
		t.Fatalf("%+v", in)
	}
}

func TestCapDropsOldestAndPersists(t *testing.T) {
	dir := t.TempDir()
	s, _ := Open(dir)
	for i := uint64(0); i < 40; i++ {
		if _, err := s.Append(cid, Meta{Cap: MinCap}, recs(i*100+1, i*100+100, 1000)); err != nil {
			t.Fatal(err)
		}
	}
	in, _ := s.Info(cid)
	if in.Size > MinCap || in.Last != 4000 || in.First <= 1 || in.Dropped != in.First-1 {
		t.Fatalf("%+v", in)
	}
	s2, _ := Open(dir)
	in2, _ := s2.Info(cid)
	if in2.First != in.First || in2.Last != 4000 || in2.Dropped != in.Dropped {
		t.Fatalf("reopen %+v vs %+v", in2, in)
	}
	got := seqs(t, s2, 0)
	if uint64(len(got)) != 4000-in.First+1 {
		t.Fatalf("read %d", len(got))
	}
}

func TestEngineGapCountsDropped(t *testing.T) {
	s, _ := Open(t.TempDir())
	s.Append(cid, Meta{}, recs(1, 3, 1))
	s.Append(cid, Meta{}, recs(8, 9, 1))
	if in, _ := s.Info(cid); in.Dropped != 4 {
		t.Fatalf("%+v", in)
	}
}

func TestDelete(t *testing.T) {
	s, _ := Open(t.TempDir())
	s.Append(cid, Meta{App: "a"}, recs(1, 3, 1))
	s.Append("abcdefabcdef", Meta{App: "b"}, recs(1, 3, 1))
	n, err := s.DeleteWhere(func(m Meta) bool { return m.App == "a" })
	if err != nil || n != 1 {
		t.Fatal(n, err)
	}
	all, _ := s.List()
	if len(all) != 1 || all[0].App != "b" {
		t.Fatalf("%+v", all)
	}
}

func frames(t *testing.T, r io.Reader) (out, errs string) {
	t.Helper()
	var h [8]byte
	for {
		if _, err := io.ReadFull(r, h[:]); err != nil {
			return
		}
		b := make([]byte, binary.BigEndian.Uint32(h[4:]))
		io.ReadFull(r, b)
		if h[0] == 2 {
			errs += string(b)
		} else {
			out += string(b)
		}
	}
}

func TestStreamTailTimestampsFollow(t *testing.T) {
	s, _ := Open(t.TempDir())
	s.Append(cid, Meta{}, []Record{
		{Seq: 1, Time: time.Unix(10, 0), Data: []byte("one")},
		{Seq: 2, Time: time.Unix(11, 0), Stderr: true, Data: []byte("err")},
		{Seq: 3, Time: time.Unix(12, 0), Data: []byte("par"), Partial: true},
		{Seq: 4, Time: time.Unix(12, 0), Data: []byte("tial")},
	})
	rc, err := s.Stream(context.Background(), cid, ReadOptions{Stdout: true, Stderr: true, Tail: 2})
	if err != nil {
		t.Fatal(err)
	}
	out, errs := frames(t, rc)
	if out != "partial\n" || errs != "" {
		t.Fatalf("tail: %q %q", out, errs)
	}
	rc, _ = s.Stream(context.Background(), cid, ReadOptions{Stderr: true, Timestamps: true})
	if _, errs := frames(t, rc); errs != "1970-01-01T00:00:11Z err\n" {
		t.Fatalf("stderr: %q", errs)
	}
	rc, _ = s.Stream(context.Background(), cid, ReadOptions{Stdout: true, TTY: true, Since: time.Unix(12, 0)})
	if b, _ := io.ReadAll(rc); string(b) != "partial\n" {
		t.Fatalf("tty since: %q", b)
	}
	ctx, cancel := context.WithCancel(context.Background())
	rc, _ = s.Stream(ctx, cid, ReadOptions{Stdout: true, TTY: true, Tail: 1, Follow: true})
	got := make(chan string, 1)
	go func() { b, _ := io.ReadAll(rc); got <- string(b) }()
	time.Sleep(50 * time.Millisecond)
	s.Append(cid, Meta{}, []Record{{Seq: 5, Time: time.Unix(13, 0), Data: []byte("five")}})
	time.Sleep(50 * time.Millisecond)
	cancel()
	if b := <-got; b != "tial\nfive\n" {
		t.Fatalf("follow: %q", b)
	}
}

type fakeEngine struct {
	held  []Record
	acked uint64
	calls int
}

func (f *fakeEngine) Bulk(_ context.Context, _ string, after uint64, max int) (Bulk, error) {
	f.calls++
	var b Bulk
	for _, r := range f.held {
		if r.Seq <= after || r.Seq <= f.acked {
			continue
		}
		if b.Count > 0 && len(b.Body)+headerSize+len(r.Data) > max {
			break
		}
		b.Body = Encode(b.Body, r)
		if b.Count == 0 {
			b.First = r.Seq
		}
		b.Last, b.Count = r.Seq, b.Count+1
	}
	return b, nil
}

func (f *fakeEngine) Ack(_ context.Context, _ string, upto uint64) error {
	if upto < f.acked {
		return fmt.Errorf("ack went back")
	}
	f.acked = upto
	return nil
}

func TestFetch(t *testing.T) {
	s, _ := Open(t.TempDir())
	e := &fakeEngine{held: recs(1, 3000, 2000)}
	n, err := s.Fetch(context.Background(), e, cid, Meta{App: "x"})
	if err != nil || n != 3000 || e.acked != 3000 || s.Last(cid) != 3000 {
		t.Fatal(n, err, e.acked)
	}
	// an ack lost before: the engine still holds what the store has
	e.acked = 2000
	if n, err := s.Fetch(context.Background(), e, cid, Meta{}); err != nil || n != 0 || e.acked != 3000 {
		t.Fatal(n, err, e.acked)
	}
}

func TestTrimBeforeKeepsNewerAndDropsLateOld(t *testing.T) {
	dir := t.TempDir()
	s, _ := Open(dir)
	// Small cap so the log spans several segments.
	if _, err := s.Append(cid, Meta{Cap: MinCap}, recs(1, 40, 64<<10)); err != nil {
		t.Fatal(err)
	}
	base := time.Date(2026, 11, 27, 0, 0, 0, 0, time.UTC)
	before := seqs(t, s, 0)
	n, err := s.TrimBefore(cid, base.Add(30*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	got := seqs(t, s, 0)
	if len(got) == 0 || got[0] != 31 || got[len(got)-1] != 40 || n != len(before)-len(got) {
		t.Fatalf("removed %d, left %v", n, got)
	}
	// The engine still had seq 41 (time 29s, queued before the clear) and 42.
	late := []Record{{Seq: 41, Time: base.Add(29 * time.Second), Data: []byte("old")}, {Seq: 42, Time: base.Add(50 * time.Second), Data: []byte("new")}}
	if last, err := s.Append(cid, Meta{}, late); err != nil || last != 42 {
		t.Fatal(last, err)
	}
	// Reopened, the clear time and the trimmed segments persist.
	s2, _ := Open(dir)
	got = seqs(t, s2, 0)
	if got[0] != 31 || got[len(got)-1] != 42 || len(got) != 11 {
		t.Fatalf("after reopen %v", got)
	}
	if _, err := s2.Append(cid, Meta{}, []Record{{Seq: 43, Time: base.Add(10 * time.Second), Data: []byte("x")}}); err != nil {
		t.Fatal(err)
	}
	if got := seqs(t, s2, 42); len(got) != 0 {
		t.Fatalf("pre-clear line kept after reopen: %v", got)
	}
	if s2.Last(cid) != 43 {
		t.Fatal("last not advanced", s2.Last(cid))
	}
}

// A crash after a segment rewrite but before the original is removed leaves
// both files; reopening keeps one copy and still hides the cleared records.
func TestTrimBeforeCrashLeftover(t *testing.T) {
	dir := t.TempDir()
	s, _ := Open(dir)
	if _, err := s.Append(cid, Meta{}, recs(1, 10, 10)); err != nil {
		t.Fatal(err)
	}
	base := time.Date(2026, 11, 27, 0, 0, 0, 0, time.UTC)
	// Simulate: clear time saved, rewritten copy written, original kept.
	l, _ := s.get(cid, nil)
	l.mu.Lock()
	l.cleared = base.Add(5 * time.Second)
	_ = l.saveMeta()
	var buf []byte
	for _, r := range recs(6, 10, 10) {
		buf = Encode(buf, r)
	}
	_ = os.WriteFile(filepath.Join(l.dir, segName(6)), buf, 0o600)
	l.mu.Unlock()
	s2, _ := Open(dir)
	got := seqs(t, s2, 0)
	if len(got) != 5 || got[0] != 6 || got[4] != 10 {
		t.Fatalf("after crash %v", got)
	}
	if n, _ := filepath.Glob(filepath.Join(dir, cid, "*.seg")); len(n) != 1 {
		t.Fatal("leftover copy kept", n)
	}
}

func TestTrimWhereMatchesMeta(t *testing.T) {
	s, _ := Open(t.TempDir())
	a, b := "aaaaaaaaaaaa", "bbbbbbbbbbbb"
	if _, err := s.Append(a, Meta{Tenant: "t", App: "web", Service: "api"}, recs(1, 5, 8)); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Append(b, Meta{Tenant: "t", App: "web", Service: "db"}, recs(1, 5, 8)); err != nil {
		t.Fatal(err)
	}
	logs, n, err := s.TrimWhere(func(m Meta) bool { return m.Service == "api" }, time.Date(2026, 11, 28, 0, 0, 0, 0, time.UTC))
	if err != nil || logs != 1 || n != 5 {
		t.Fatal(logs, n, err)
	}
	in, err := s.Info(b)
	if err != nil || in.Last != 5 || in.First != 1 {
		t.Fatal("other service touched", in, err)
	}
}
