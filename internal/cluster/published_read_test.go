// SPDX-License-Identifier: Apache-2.0

package cluster

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"github.com/jay94ks/seafield/internal/cluster/state"
	"github.com/jay94ks/seafield/internal/storage"

	"github.com/hashicorp/raft"
)

func TestLocalReadUsesDurablePublicationDuringWriterWork(t *testing.T) {
	db, err := storage.Open(filepath.Join(t.TempDir(), "fsm.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	f, err := newFSM(db, raft.NewInmemStore(), "cluster", "admin", nil)
	if err != nil {
		t.Fatal(err)
	}
	apply := func(index uint64, key string) application {
		raw, err := state.EncodeCommand(state.Command{Actor: "admin", Epoch: 1, RequestID: key, Key: "network/" + key, Value: "committed"})
		if err != nil {
			t.Fatal(err)
		}
		return f.Apply(&raft.Log{Index: index, Term: 1, Type: raft.LogCommand, Data: raw}).(application)
	}
	if reply := apply(1, "first"); reply.Err != nil || reply.Result.Code != state.Applied {
		t.Fatal(reply)
	}
	e := &Engine{fsm: f}
	f.mu.Lock()
	locked := true
	defer func() {
		if locked {
			f.mu.Unlock()
		}
	}()
	original := f.work
	f.work, _ = state.New("unpublished-candidate")
	result := make(chan View, 1)
	readErrors := make(chan error, 1)
	go func() {
		v, err := e.Read(context.Background(), false)
		result <- v
		readErrors <- err
	}()
	var old View
	select {
	case old = <-result:
		if err := <-readErrors; err != nil {
			t.Fatal(err)
		}
		if old.RaftIndex != 1 || old.Term != 1 || old.State.Object("network/first").Value != "committed" {
			t.Fatal("local read did not retain original durable publication", old)
		}
	case <-time.After(100 * time.Millisecond):
		t.Fatal("local published read blocked behind candidate/writer I/O")
	}
	subscribed := make(chan (<-chan struct{}), 1)
	go func() { subscribed <- e.Changes() }()
	select {
	case changed := <-subscribed:
		select {
		case <-changed:
			t.Fatal("unpublished writer candidate signaled a change")
		default:
		}
	case <-time.After(100 * time.Millisecond):
		t.Fatal("durable change subscription blocked behind candidate/writer I/O")
	}
	for _, minimum := range []uint64{1, 2} {
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
		finished := make(chan error, 1)
		go func() {
			v, err := e.ReadAtLeast(ctx, minimum)
			if minimum == 1 && (err != nil || v.State.Index() != 1) {
				finished <- fmt.Errorf("covered original floor: index=%d error=%v", v.State.Index(), err)
			} else if minimum == 2 && !errors.Is(err, context.DeadlineExceeded) {
				finished <- fmt.Errorf("missing floor ignored original deadline: %v", err)
			} else {
				finished <- nil
			}
		}()
		select {
		case err := <-finished:
			cancel()
			if err != nil {
				t.Fatal(err)
			}
		case <-time.After(100 * time.Millisecond):
			cancel()
			t.Fatal("local permit read waited for candidate instead of original context")
		}
	}
	f.work = original
	f.mu.Unlock()
	locked = false
	if reply := apply(2, "second"); reply.Err != nil || reply.Result.Code != state.Applied {
		t.Fatal(reply)
	}
	now, err := e.Read(context.Background(), false)
	if err != nil || now.RaftIndex != 2 || now.State.Object("network/second").Value != "committed" || old.State.Object("network/second").Present {
		t.Fatal("publication order or previous immutable state changed", err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	if reply := apply(3, "failed"); reply.Err == nil {
		t.Fatal("failed sync published")
	}
	for _, strict := range []bool{false, true} {
		if _, _, _, err := f.view(strict); err == nil {
			t.Fatal("read served after fatal sync", strict)
		}
	}
}
