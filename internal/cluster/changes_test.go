// SPDX-License-Identifier: Apache-2.0

package cluster

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/jay94ks/seafield/internal/cluster/state"
	"github.com/jay94ks/seafield/internal/storage"

	"github.com/hashicorp/raft"
)

func TestDurableChangesBroadcastIndependentWatchersAndSyncFailure(t *testing.T) {
	db, err := storage.Open(filepath.Join(t.TempDir(), "fsm.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	f, err := newFSM(db, raft.NewInmemStore(), "cluster", "admin", nil)
	if err != nil {
		t.Fatal(err)
	}
	e := &Engine{fsm: f}
	first, second := e.Changes(), e.Changes()
	apply := func(index uint64, key string) application {
		t.Helper()
		raw, err := state.EncodeCommand(state.Command{Actor: "admin", Epoch: 1, RequestID: key, Key: "network/" + key, Value: "committed"})
		if err != nil {
			t.Fatal(err)
		}
		return f.Apply(&raft.Log{Index: index, Term: 1, Type: raft.LogCommand, Data: raw}).(application)
	}
	if reply := apply(1, "first"); reply.Err != nil || reply.Result.Code != state.Applied {
		t.Fatal(reply)
	}
	for _, watcher := range []<-chan struct{}{first, second} {
		select {
		case <-watcher:
		default:
			t.Fatal("another watcher consumed notification")
		}
	}
	third := e.Changes()
	if third == first {
		t.Fatal("published notification generation not replaced")
	}
	select {
	case <-third:
		t.Fatal("future generation already notified")
	default:
	}
	view, index, _, err := f.view(false)
	if err != nil || index != 1 || view.Object("network/first").Value != "committed" {
		t.Fatal("watcher preceded durable publication", err)
	}
	if reply := apply(2, "second"); reply.Err != nil || reply.Result.Code != state.Applied {
		t.Fatal(reply)
	}
	select {
	case <-third:
	default:
		t.Fatal("second publication not broadcast")
	}
	failed := e.Changes()
	if err = db.Close(); err != nil {
		t.Fatal(err)
	}
	if reply := apply(3, "unsynced"); reply.Err == nil {
		t.Fatal("lost sync accepted")
	}
	select {
	case <-failed:
		t.Fatal("failed candidate woke published-state watcher")
	default:
	}
}

func TestLocalPermitReadWaitsForDurableCommandOrdinalAndKeepsOriginalDeadline(t *testing.T) {
	db, err := storage.Open(filepath.Join(t.TempDir(), "fsm.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	f, err := newFSM(db, raft.NewInmemStore(), "cluster", "admin", nil)
	if err != nil {
		t.Fatal(err)
	}
	// No Raft/transport is installed: this read may only await local durable
	// publication, never renew a permit or submit an effect.
	e := &Engine{fsm: f, done: make(chan struct{})}
	apply := func(index uint64, key string) application {
		t.Helper()
		raw, err := state.EncodeCommand(state.Command{Actor: "admin", Epoch: 1, RequestID: key, Key: "network/" + key, Value: "committed"})
		if err != nil {
			t.Fatal(err)
		}
		return f.Apply(&raft.Log{Index: index, Term: 1, Type: raft.LogCommand, Data: raw}).(application)
	}
	if got := apply(10, "first"); got.Err != nil || got.Result.Code != state.Applied {
		t.Fatal(got)
	}
	t.Run("raft-position-is-not-command-ordinal", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
		defer cancel()
		if _, err := e.ReadAtLeast(ctx, 2); !errors.Is(err, context.DeadlineExceeded) {
			t.Fatal("Raft index10 admitted missing command2", err)
		}
	})
	t.Run("cancellation-even-if-floor-already-covered", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		if _, err := e.ReadAtLeast(ctx, 1); !errors.Is(err, context.Canceled) {
			t.Fatal(err)
		}
	})
	t.Run("all-readers-observe-original-floor-after-commit", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		type outcome struct {
			view View
			err  error
		}
		results := make(chan outcome, 2)
		for range 2 {
			go func() { v, err := e.ReadAtLeast(ctx, 2); results <- outcome{v, err} }()
		}
		if got := apply(20, "second"); got.Err != nil || got.Result.Code != state.Applied {
			t.Fatal(got)
		}
		for range 2 {
			select {
			case result := <-results:
				if result.err != nil || !result.view.Local || result.view.State.Index() != 2 || result.view.RaftIndex != 20 || result.view.State.Object("network/second").Value != "committed" {
					t.Fatal("grant not covered by durable local prefix", result.err, result.view.State.Index(), result.view.RaftIndex)
				}
			case <-ctx.Done():
				t.Fatal(ctx.Err())
			}
		}
	})
	t.Run("close-interrupts-missing-floor", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		closed := &Engine{fsm: f, done: make(chan struct{})}
		close(closed.done)
		if _, err := closed.ReadAtLeast(ctx, 3); !errors.Is(err, raft.ErrRaftShutdown) {
			t.Fatal(err)
		}
	})
	t.Run("failed-sync-cannot-admit-old-published-view", func(t *testing.T) {
		if err := db.Close(); err != nil {
			t.Fatal(err)
		}
		if got := apply(30, "unsynced"); got.Err == nil {
			t.Fatal("lost sync accepted")
		}
		if _, err := e.ReadAtLeast(context.Background(), 2); err == nil {
			t.Fatal("failure returned an old successful permit view")
		}
	})
}
