// SPDX-License-Identifier: Apache-2.0

package reconcile

import (
	"context"
	"errors"
	"path/filepath"
	"reflect"
	"testing"
)

func TestLeaseResizePreservesOutstandingAndDrain(t *testing.T) {
	l, _ := NewLeases(9, 3)
	a, _ := l.Acquire()
	b, _ := l.Acquire()
	c, _ := l.Acquire()
	if err := l.Resize(1); err != nil {
		t.Fatal(err)
	}
	l, err := RestoreLeases(l.Checkpoint())
	if err != nil || l.Count() != 3 {
		t.Fatal("shrunk checkpoint discarded users", err)
	}
	if _, err = l.Acquire(); !errors.Is(err, ErrLease) {
		t.Fatal("over-budget borrow", err)
	}
	if err = l.Release(a); err != nil {
		t.Fatal(err)
	}
	if err = l.Release(b); err != nil {
		t.Fatal(err)
	}
	if _, err = l.Acquire(); !errors.Is(err, ErrLease) {
		t.Fatal("full resized budget ignored", err)
	}
	if err = l.Release(c); err != nil {
		t.Fatal(err)
	}
	fresh, err := l.Acquire()
	if err != nil || fresh.Token <= c.Token {
		t.Fatal("resize reset floor", fresh, err)
	}
	if err = l.Release(c); err == nil || l.Count() != 1 {
		t.Fatal("stale receipt consumed new user")
	}
	l.Drain()
	if err = l.Resize(8); err != nil {
		t.Fatal(err)
	}
	l, err = RestoreLeases(l.Checkpoint())
	if err != nil {
		t.Fatal(err)
	}
	if _, err = l.Acquire(); err == nil {
		t.Fatal("resize cleared Drain")
	}
	if err = l.Resize(0); err == nil {
		t.Fatal("zero budget")
	}
	if err = l.Replace(10); err == nil {
		t.Fatal("resized live lease retired")
	}
	if err = l.Release(fresh); err != nil {
		t.Fatal(err)
	}
	if err = l.Replace(10); err != nil {
		t.Fatal(err)
	}
	newGeneration, err := l.Acquire()
	if err != nil || newGeneration.Token <= fresh.Token {
		t.Fatal("new generation reused resized token", err)
	}
}

func TestRealBoundaryJournalResizeIsAtomicAndDurable(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "module.db")
	j, err := OpenJournal(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = j.Close() }()
	d := &fileDriver{path: filepath.Join(root, "effect"), j: j, t: t}
	desired := Desired{Revision: 1, Resource: Resource{Generation: 1, Spec: "original", Present: true}}
	if err = j.Desired("bridge", desired, 3); err != nil {
		t.Fatal(err)
	}
	if err = j.Step(context.Background(), "bridge", d); err != nil {
		t.Fatal(err)
	}
	a, err := j.Borrow("bridge", "a", 1)
	if err != nil {
		t.Fatal(err)
	}
	b, err := j.Borrow("bridge", "b", 1)
	if err != nil {
		t.Fatal(err)
	}
	if err = j.Desired("bridge", desired, 1); err != nil {
		t.Fatal(err)
	}
	if err = j.Close(); err != nil {
		t.Fatal(err)
	}
	j, err = OpenJournal(path)
	if err != nil {
		t.Fatal(err)
	}
	d.j = j
	r, err := j.Read("bridge")
	if err != nil || r.Capacity != 1 || r.Pins.Capacity != 1 || len(r.Consumers) != 2 {
		t.Fatal("resize lost durable users", r, err)
	}
	if _, err = j.Borrow("bridge", "new", 1); err == nil {
		t.Fatal("borrow under excess budget")
	}
	if err = j.Return("bridge", "a", a); err != nil {
		t.Fatal(err)
	}
	if err = j.Return("bridge", "b", b); err != nil {
		t.Fatal(err)
	}
	fresh, err := j.Borrow("bridge", "new", 1)
	if err != nil || fresh.Token <= b.Token {
		t.Fatal("reopened resize floor", fresh, err)
	}
	before, err := j.Read("bridge")
	if err != nil {
		t.Fatal(err)
	}
	// A closed underlying DB injects a real write failure without bypassing the
	// journal's uncertain-write fence. Stale memory is unreadable until the
	// same durable journal is reopened; the original full record must survive.
	if err = j.db.Close(); err != nil {
		t.Fatal(err)
	}
	next := Desired{Revision: 2}
	if err = j.Desired("bridge", next, 4); err == nil {
		t.Fatal("failed resize was accepted")
	}
	if _, err = j.Read("bridge"); !errors.Is(err, ErrJournalUncertain) {
		t.Fatal("failed resize exposed stale in-memory state", err)
	}
	if _, err = j.Borrow("bridge", "late", 1); !errors.Is(err, ErrJournalUncertain) {
		t.Fatal("failed resize admitted a new consumer", err)
	}
	if err = j.Close(); err != nil {
		t.Fatal(err)
	}
	j, err = OpenJournal(path)
	if err != nil {
		t.Fatal(err)
	}
	d.j = j
	after, err := j.Read("bridge")
	if err != nil || !reflect.DeepEqual(after, before) || after.Consumers["new"] != fresh {
		t.Fatal("failed resize changed original durable state", after, err)
	}
}
