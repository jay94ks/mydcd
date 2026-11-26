// SPDX-License-Identifier: Apache-2.0

package workload

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"path/filepath"
	"testing"
)

// Real A3 journal/reopen; native SDK facts are supplied by the existing fixture.
func TestServiceCallStartupSettlesOnlyPreviousOwnedHTTPReaders(t *testing.T) {
	f := makeStartFixture(t)
	path := filepath.Join(t.TempDir(), "workload.db")
	m, err := OpenManager(path, f.engine, f.bridge)
	if err != nil {
		t.Fatal(err)
	}
	if err = m.Desired("task", 1, 1, &f.spec, 8); err != nil {
		t.Fatal(err)
	}
	if err = m.journal.Step(context.Background(), "task", readProbeAppliedFixture{}); err != nil {
		t.Fatal(err)
	}
	run := sha256.Sum256([]byte("old process HTTP"))
	call := sha256.Sum256([]byte("one request"))
	id := hex.EncodeToString(run[:])
	httpLease, err := m.BorrowServiceCall(context.Background(), "task", 1, 1, f.native.ID, id, call)
	if err != nil {
		t.Fatal(err)
	}
	checker, err := m.BorrowReadProbe(context.Background(), "task", 1, 1, f.native.ID, id, call)
	if err != nil {
		t.Fatal(err)
	}
	if httpLease.consumer() == checker.consumer() {
		t.Fatal("consumer namespaces overlap")
	}
	if err = m.Close(); err != nil {
		t.Fatal(err)
	}
	m, err = OpenManager(path, f.engine, f.bridge)
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	if err = m.RecoverServiceCalls(context.Background()); err != nil {
		t.Fatal(err)
	}
	record, err := m.View("task")
	if err != nil {
		t.Fatal(err)
	}
	if len(record.Consumers) != 1 || record.Consumers[checker.consumer()] != checker.Pin {
		t.Fatal("startup returned another reader or retained dead HTTP pin")
	}
	if err = m.ReturnReadProbe(checker); err != nil {
		t.Fatal(err)
	}
	if err = m.RecoverServiceCalls(context.Background()); err != nil {
		t.Fatal(err)
	}
	if f.starts != 0 || f.stops != 0 || f.removes != 0 {
		t.Fatal("startup reader settlement performed a container effect")
	}
	for _, bad := range []string{"service-call/foreign", "checker-read/" + id + "/" + id, "service-call/" + id + "/../" + id} {
		if validServiceCallConsumer(bad) {
			t.Fatal("foreign reader accepted", bad)
		}
	}
}
