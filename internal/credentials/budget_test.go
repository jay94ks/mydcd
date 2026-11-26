// SPDX-License-Identifier: Apache-2.0

package credentials

import (
	"context"
	"fmt"
	"testing"
	"time"
)

func TestCredentialBudgetRateConcurrencyCancelAndClock(t *testing.T) {
	b := NewBudget()
	now := time.Unix(100, 0)
	ctx := context.Background()
	release, err := b.Begin(ctx, "alice", "127.0.0.1", now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := b.Begin(ctx, "bob", "127.0.0.2", now); err == nil {
		t.Fatal("concurrent expensive verifier admitted")
	}
	release()
	release()
	for i := 0; i < 4; i++ {
		done, err := b.Begin(ctx, "alice", "127.0.0.1", now)
		if err != nil {
			t.Fatal(i, err)
		}
		done()
	}
	if _, err := b.Begin(ctx, "alice", "127.0.0.1", now); err == nil {
		t.Fatal("username burst exceeded")
	}
	if _, err := b.Begin(ctx, "new", "new", now.Add(-time.Second)); err == nil {
		t.Fatal("clock rollback refreshed budget")
	}
	dead, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := b.Begin(dead, "fresh", "fresh", now.Add(time.Second)); err == nil {
		t.Fatal("canceled work allocated permit")
	}
	done, err := b.Begin(ctx, "alice", "127.0.0.1", now.Add(12*time.Second))
	if err != nil {
		t.Fatal("library refill", err)
	}
	done()
	for i := 0; i < 10; i++ {
		done, err := b.Begin(ctx, fmt.Sprint("u", i), "source", now.Add(60*time.Second))
		if err != nil {
			t.Fatal(i, err)
		}
		done()
	}
	if _, err := b.Begin(ctx, "another", "source", now.Add(60*time.Second)); err == nil {
		t.Fatal("source limit bypassed by rotated username/key")
	}
}

func TestCredentialBudgetBoundedKeysGlobalBurstAndRetirement(t *testing.T) {
	b := NewBudget()
	ctx := context.Background()
	now := time.Unix(100, 0)
	for i := 0; i < 20; i++ {
		done, err := b.Begin(ctx, fmt.Sprint("u", i), fmt.Sprint("s", i), now)
		if err != nil {
			t.Fatal(i, err)
		}
		done()
	}
	if _, err := b.Begin(ctx, "next", "next", now); err == nil {
		t.Fatal("global burst exceeded")
	}
	// Spread input times to stay inside all library rates while exercising only
	// bounded table capacity and its idle retirement; no actual sleeping/load.
	for i := 20; i < 1024; i++ {
		done, err := b.Begin(ctx, fmt.Sprint("u", i), fmt.Sprint("s", i), now.Add(time.Duration(i)*time.Second))
		if err != nil {
			t.Fatal(i, err)
		}
		done()
	}
	if len(b.users) > 1024 || len(b.sources) > 1024 {
		t.Fatal("unbounded admission maps")
	}
	done, err := b.Begin(ctx, "replacement", "replacement", now.Add(2000*time.Second))
	if err != nil {
		t.Fatal("idle entries not retired", err)
	}
	done()
	if len(b.users) >= 1024 || len(b.sources) >= 1024 {
		t.Fatal("idle bounded entries retained forever")
	}
}

func TestCredentialBudgetRejectedUserDoesNotSpendOtherUsersSharedUIDBudget(t *testing.T) {
	b := NewBudget()
	ctx, now := context.Background(), time.Unix(100, 0)
	for range 5 {
		release, err := b.Begin(ctx, "failed-user", "unix-uid:1000", now)
		if err != nil {
			t.Fatal(err)
		}
		release()
	}
	for range 50 {
		if _, err := b.Begin(ctx, "failed-user", "unix-uid:1000", now); err == nil {
			t.Fatal("failed user's cap bypassed")
		}
	}
	for _, user := range []string{"second", "third", "fourth"} {
		release, err := b.Begin(ctx, user, "unix-uid:1000", now)
		if err != nil {
			t.Fatal("rejected user consumed shared UID/global budget", user, err)
		}
		release()
	}
}
