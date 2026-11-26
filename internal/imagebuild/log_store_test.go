// SPDX-License-Identifier: Apache-2.0

package imagebuild

import (
	"bytes"
	"errors"
	"io"
	"testing"

	bolt "go.etcd.io/bbolt"
)

func TestBuildLogsTailReads400KiBAndFollowsOnlyNewBytes(t *testing.T) {
	f := newNativeFixture(t, false)
	w, err := f.jobs.OpenLogWriter(f.ctx(), f.spec)
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	for _, size := range []int{0, 17, 400 << 10} {
		if size != 0 {
			prior := 0
			if size > 17 {
				prior = 17
			}
			if _, err := w.Write(bytes.Repeat([]byte{'x'}, size-prior)); err != nil {
				t.Fatal(err)
			}
		}
		if err := w.Flush(); err != nil {
			t.Fatal(err)
		}
		// The non-aligned window also exercises crossing storage chunk boundaries.
		for _, limit := range []uint32{1, 12345, MaxLogPageBytes} {
			page, err := ReadNativeLogsTail(f.db, f.spec, limit)
			offset := uint32(size) - min(uint32(size), limit)
			if err != nil || !page.Valid(f.spec.Digest(), offset, limit) || page.Total != uint32(size) || page.Next != uint32(size) || !bytes.Equal(page.Data, bytes.Repeat([]byte{'x'}, int(min(uint32(size), limit)))) {
				t.Fatal("tail did not select the final bytes", size, limit, err)
			}
		}
	}
	page, err := ReadNativeLogsTail(f.db, f.spec, MaxLogPageBytes)
	if err != nil {
		t.Fatal(err)
	}
	if idle, err := ReadNativeLogs(f.db, f.spec, page.Next, MaxLogPageBytes); err != nil || idle.Next != page.Next || len(idle.Data) != 0 {
		t.Fatal("EOF cursor cannot be polled", err)
	}
	suffix := []byte("only the newly appended output\n")
	if _, err := w.Write(suffix); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	follow, err := ReadNativeLogs(f.db, f.spec, page.Next, MaxLogPageBytes)
	if err != nil || !follow.Valid(f.spec.Digest(), page.Next, MaxLogPageBytes) || !bytes.Equal(follow.Data, suffix) || follow.Unclosed {
		t.Fatal("tail cursor lost or repeated prior output", err)
	}
}

// Native observations DB is real; authority remains the injected fixture.
// No Docker execution or user/owner quorum is claimed by these store tests.
func TestBuildLogsAppendAcrossPartialChunksAndKeepCursorAfterGrowth(t *testing.T) {
	f := newNativeFixture(t, false)
	w, err := f.jobs.OpenLogWriter(f.ctx(), f.spec)
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	if _, err := f.jobs.OpenLogWriter(f.ctx(), f.spec); !errors.Is(err, ErrUsed) {
		t.Fatal("second writer", err)
	}
	first := bytes.Repeat([]byte("filtered-output\n"), 700)
	if n, err := w.Write(first); n != len(first) || err != nil {
		t.Fatal(n, err)
	}
	if err := w.Flush(); err != nil {
		t.Fatal(err)
	}
	page, err := ReadNativeLogs(f.db, f.spec, 0, 3000)
	if err != nil || !page.Valid(f.spec.Digest(), 0, 3000) || !page.Unclosed || !bytes.Equal(page.Data, first[:3000]) {
		t.Fatal(page, err)
	}
	second := []byte("new redacted suffix")
	if _, err := w.Write(second); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write(second); !errors.Is(err, io.ErrClosedPipe) {
		t.Fatal("closed stream wrote", err)
	}
	want := append(bytes.Clone(first), second...)
	var got []byte
	var offset uint32
	for offset < uint32(len(want)) {
		p, err := ReadNativeLogs(f.db, f.spec, offset, 3000)
		if err != nil || !p.Valid(f.spec.Digest(), offset, 3000) || p.Unclosed {
			t.Fatal(p, err)
		}
		got = append(got, p.Data...)
		offset = p.Next
	}
	if !bytes.Equal(got, want) {
		t.Fatal("append/cursor rewrote original output")
	}
	tail, err := ReadNativeLogs(f.db, f.spec, offset, 3000)
	if err != nil || len(tail.Data) != 0 || tail.Next != offset {
		t.Fatal("tail polling", tail, err)
	}
	if _, err := ReadNativeLogs(f.db, f.spec, offset+1, 3000); !errors.Is(err, ErrConflict) {
		t.Fatal("future offset", err)
	}
	got[0] ^= 1
	page, err = ReadNativeLogs(f.db, f.spec, 0, 3000)
	if err != nil || !bytes.Equal(page.Data, first[:3000]) {
		t.Fatal("caller mutated DB bytes", err)
	}
}

func TestBuildLogsRecoveryMarksGapAndOldWriterCannotReplaceNewSession(t *testing.T) {
	f := newNativeFixture(t, false)
	old, err := f.jobs.OpenLogWriter(f.ctx(), f.spec)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := old.Write([]byte("before\n")); err != nil {
		t.Fatal(err)
	}
	if err := old.Flush(); err != nil {
		t.Fatal(err)
	}
	f.reopen() // process interruption: original Unclosed is still durable
	page, err := ReadNativeLogs(f.db, f.spec, 0, 4096)
	if err != nil || !page.Unclosed || page.Gap {
		t.Fatal(page, err)
	}
	next, err := f.jobs.OpenLogWriter(f.ctx(), f.spec)
	if err != nil {
		t.Fatal(err)
	}
	defer next.Close()
	if err := old.Close(); !errors.Is(err, ErrConflict) {
		t.Fatal("old session closed new stream", err)
	}
	if _, err := next.Write([]byte("after\n")); err != nil {
		t.Fatal(err)
	}
	if err := next.Close(); err != nil {
		t.Fatal(err)
	}
	page, err = ReadNativeLogs(f.db, f.spec, 0, 4096)
	if err != nil || !page.Gap || page.Unclosed || string(page.Data) != "before\nafter\n" {
		t.Fatal(page, err)
	}
}

func TestBuildLogInterruptionMarksGapWithoutFabricatingAnotherSession(t *testing.T) {
	f := newNativeFixture(t, false)
	w, err := f.jobs.OpenLogWriter(f.ctx(), f.spec)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write([]byte("redacted prefix")); err != nil {
		t.Fatal(err)
	}
	if err := f.jobs.MarkLogGap(f.spec); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	page, err := ReadNativeLogs(f.db, f.spec, 0, 4096)
	if err != nil || !page.Gap || page.Unclosed || string(page.Data) != "redacted prefix" {
		t.Fatal(page, err)
	}
	if err := f.jobs.MarkLogGap(f.spec); err != nil {
		t.Fatal("gap reentry", err)
	}
}

func TestBuildLogLimitKeepsDrainingAndDoesNotOverwriteEarlierChunks(t *testing.T) {
	f := newNativeFixture(t, false)
	w, err := f.jobs.OpenLogWriter(f.ctx(), f.spec)
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	chunk := bytes.Repeat([]byte{'x'}, LogChunkBytes)
	for bytes := 0; bytes <= MaxLogBytes; bytes += len(chunk) {
		if n, err := w.Write(chunk); err != nil || n != len(chunk) {
			t.Fatal("limit stopped SDK draining", n, err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	page, err := ReadNativeLogs(f.db, f.spec, MaxLogBytes-10, 4096)
	if err != nil || !page.Truncated || page.Total != MaxLogBytes || len(page.Data) != 10 || page.Unclosed {
		t.Fatal(page, err)
	}
}

type failingLogStore struct {
	Transactions
	fail bool
}

var errLogStoreCommit = errors.New("injected log DB commit failure")

func (d *failingLogStore) Update(fn func(*bolt.Tx) error) error {
	if d.fail {
		return errLogStoreCommit
	}
	return d.Transactions.Update(fn)
}
func TestBuildLogFailedCloseKeepsUnclosedAndMissingOriginalBytesAreNotRepaired(t *testing.T) {
	f := newNativeFixture(t, false)
	db := &failingLogStore{Transactions: f.db}
	f.jobs.db = db
	w, err := f.jobs.OpenLogWriter(f.ctx(), f.spec)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write([]byte("original")); err != nil {
		t.Fatal(err)
	}
	if err := w.Flush(); err != nil {
		t.Fatal(err)
	}
	db.fail = true
	if err := w.Close(); !errors.Is(err, errLogStoreCommit) {
		t.Fatal(err)
	}
	page, err := ReadNativeLogs(f.db, f.spec, 0, 4096)
	if err != nil || !page.Unclosed || string(page.Data) != "original" {
		t.Fatal("failed close erased unknown state", page, err)
	}
	if err := f.db.Update(func(tx *bolt.Tx) error { return tx.Bucket(nativeBucket).Delete(logChunkKey(f.spec, 0)) }); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadNativeLogs(f.db, f.spec, 0, 4096); !errors.Is(err, ErrStorage) {
		t.Fatal("missing chunk became empty log", err)
	}
}

func TestBuildLogReclaimRequiresSameNativeCompletionAndPreservesJobJournal(t *testing.T) {
	f := newNativeFixture(t, false)
	ctx := f.ctx()
	w, err := f.jobs.OpenLogWriter(ctx, f.spec)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write([]byte("redacted job log")); err != nil {
		t.Fatal(err)
	}
	if err := f.jobs.PruneLogs(f.spec, JobClosure{}); !errors.Is(err, ErrUsed) {
		t.Fatal("live/unsettled logs reclaimed", err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	if err := f.jobs.ObserveExit(ctx, f.spec, true); err != nil {
		t.Fatal(err)
	}
	if _, err := f.jobs.FinishWorkspace(ctx, f.spec); err != nil {
		t.Fatal(err)
	}
	if err := f.jobs.BeginRootReturn(f.spec, JobRoot); err != nil {
		t.Fatal(err)
	}
	if err := f.jobs.FinishRootReturn(f.spec, JobRoot); err != nil {
		t.Fatal(err)
	}
	_, key := testScope(1, [32]byte{1})
	closure, err := f.jobs.SealCompletion(f.grant, JobResult{Code: "BUILD_FAILED"}, 103, key)
	if err != nil {
		t.Fatal(err)
	}
	bad := closure
	bad.Native[0] ^= 1
	if err := f.jobs.PruneLogs(f.spec, bad); !errors.Is(err, ErrConflict) {
		t.Fatal("wrong closure reclaimed logs", err)
	}
	if err := f.jobs.PruneLogs(f.spec, closure); err != nil {
		t.Fatal(err)
	}
	if err := f.jobs.PruneLogs(f.spec, closure); err != nil {
		t.Fatal("lost reclaim acknowledgement", err)
	}
	page, err := ReadNativeLogs(f.db, f.spec, 0, 4096)
	if err != nil || page.Available {
		t.Fatal(page, err)
	}
	record, err := f.jobs.Record(f.spec)
	if err != nil || record.Completion == nil || !record.Completion.Valid(f.spec) {
		t.Fatal("reclaim removed original job/completion", err)
	}
	if err := f.db.View(func(tx *bolt.Tx) error {
		if tx.Bucket(nativeBucket).Get(logChunkKey(f.spec, 0)) != nil {
			t.Fatal("reclaimed bytes retained")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := f.jobs.OpenLogWriter(ctx, f.spec); !errors.Is(err, ErrConflict) {
		t.Fatal("completed job logs recreated", err)
	}
}
