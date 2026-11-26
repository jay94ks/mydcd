// SPDX-License-Identifier: Apache-2.0

package workload

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jay94ks/mydcd/internal/engine"
	"github.com/jay94ks/mydcd/internal/reconcile"
)

// The journal is real. The existing SDK fixture supplies only native facts;
// these tests cannot prove Docker or kernel readiness.
type readProbeAppliedFixture struct{}

func (readProbeAppliedFixture) Execute(context.Context, string, reconcile.Operation) (reconcile.Outcome, error) {
	return reconcile.EffectApplied, nil
}
func (readProbeAppliedFixture) Recover(context.Context, string, reconcile.Operation) (reconcile.Outcome, error) {
	return reconcile.EffectApplied, nil
}

func TestReadProbePinsOriginalBeforeSingleNativeLookupAndKeepsFailedPin(t *testing.T) {
	for _, mode := range []string{"current", "foreign-native", "inspect-failed", "canceled", "desired-changed", "pin-returned"} {
		t.Run(mode, func(t *testing.T) {
			f := makeStartFixture(t)
			path := filepath.Join(t.TempDir(), "workload.db")
			m, err := OpenManager(path, f.engine, f.bridge)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = m.Close() })
			if err = m.Desired("task", 1, 1, &f.spec, 8); err != nil {
				t.Fatal(err)
			}
			if err = m.journal.Step(context.Background(), "task", readProbeAppliedFixture{}); err != nil {
				t.Fatal(err)
			}
			run := sha256.Sum256([]byte("original-run"))
			call := sha256.Sum256([]byte("original-call"))
			runID := hex.EncodeToString(run[:])
			consumer := "checker-read/" + runID + "/" + hex.EncodeToString(call[:])
			native := f.native.ID
			if mode == "foreign-native" {
				f.native.ID = strings.Repeat("c", 64)
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			inspections := 0
			f.onInspect = func() error {
				inspections++
				original, e := m.View("task")
				if e != nil || original.Consumers[consumer].Generation != 1 {
					t.Fatal("SDK lookup preceded the original durable pin", e)
				}
				switch mode {
				case "inspect-failed":
					return io.ErrUnexpectedEOF
				case "canceled":
					cancel()
				case "desired-changed":
					if e = m.Desired("task", 2, 1, &f.spec, 8); e != nil {
						t.Fatal(e)
					}
				case "pin-returned":
					if e = m.journal.Return("task", consumer, original.Consumers[consumer]); e != nil {
						t.Fatal(e)
					}
				}
				return nil
			}
			lease, err := m.BorrowReadProbe(ctx, "task", 1, 1, native, runID, call)
			if inspections != 1 || lease.Pin.Generation != 1 || lease.Pin.Token == 0 || lease.Target.Status.NativeID != native {
				t.Fatal("lost original pin/identity or repeated SDK lookup", inspections, lease.Pin, err)
			}
			if (mode == "current") != (err == nil) {
				t.Fatal("native/state uncertainty became success", mode, err)
			}
			if mode == "foreign-native" && !errors.Is(err, engine.ErrOwnership) {
				t.Fatal("foreign native was adopted", err)
			}
			if mode == "canceled" && !errors.Is(err, context.Canceled) {
				t.Fatal("native cancellation was lost", err)
			}
			if err = m.Close(); err != nil {
				t.Fatal(err)
			}
			m, err = OpenManager(path, f.engine, f.bridge)
			if err != nil {
				t.Fatal(err)
			}
			record, err := m.View("task")
			if err != nil {
				t.Fatal(err)
			}
			if mode == "pin-returned" {
				if _, found := record.Consumers[consumer]; found {
					t.Fatal("returned pin was fabricated after reopen")
				}
			} else {
				if record.Consumers[consumer] != lease.Pin {
					t.Fatal("failed/successful lookup erased the original pin across reopen")
				}
				if err = m.ReturnReadProbe(lease); err != nil {
					t.Fatal("exact original pin could not be returned", err)
				}
			}
			record, err = m.View("task")
			if err != nil || len(record.Consumers) != 0 {
				t.Fatal("original read consumer was not settled", err)
			}
			if f.starts != 0 || f.stops != 0 || f.removes != 0 {
				t.Fatal("read lookup performed a container effect")
			}
		})
	}
}

func TestReadProbeInvalidOriginalReferenceNeverInspectsNative(t *testing.T) {
	f := makeStartFixture(t)
	m, err := OpenManager(filepath.Join(t.TempDir(), "workload.db"), f.engine, f.bridge)
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	if err = m.Desired("task", 1, 1, &f.spec, 8); err != nil {
		t.Fatal(err)
	}
	if err = m.journal.Step(context.Background(), "task", readProbeAppliedFixture{}); err != nil {
		t.Fatal(err)
	}
	inspections := 0
	f.onInspect = func() error { inspections++; return nil }
	run := sha256.Sum256([]byte("run"))
	call := sha256.Sum256([]byte("call"))
	runID := hex.EncodeToString(run[:])
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	for _, q := range []struct {
		ctx                  context.Context
		generation, revision uint64
		native, run          string
		call                 [32]byte
	}{
		{context.Background(), 2, 2, f.native.ID, runID, call},
		{context.Background(), 1, 2, f.native.ID, runID, call},
		{context.Background(), 1, 1, "", runID, call},
		{context.Background(), 1, 1, f.native.ID, strings.Repeat("0", 64), call},
		{context.Background(), 1, 1, f.native.ID, runID, [32]byte{}},
		{canceled, 1, 1, f.native.ID, runID, call},
		{nil, 1, 1, f.native.ID, runID, call},
	} {
		lease, e := m.BorrowReadProbe(q.ctx, "task", q.generation, q.revision, q.native, q.run, q.call)
		if e == nil || lease.Pin != (reconcile.Lease{}) || inspections != 0 {
			t.Fatal("invalid original reached native lookup or acquired a consumer", lease.Pin, e)
		}
	}
	record, err := m.View("task")
	if err != nil || len(record.Consumers) != 0 {
		t.Fatal("invalid reference left a read consumer", err)
	}
}
