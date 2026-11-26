// SPDX-License-Identifier: Apache-2.0

package app

import (
	"context"
	"errors"
	"testing"
)

func TestCheckerSourceAuthorityEachEdgeIsFreshAndThenResolves(t *testing.T) {
	var calls []string
	check := checkerSourceAuthorizer(func(context.Context) error { calls = append(calls, "fresh"); return nil }, func(context.Context) error { calls = append(calls, "current-source"); return nil })
	if len(calls) != 0 {
		t.Fatal("construction dispatched authority or source I/O")
	}
	for i := 0; i < 2; i++ {
		if err := check(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	want := []string{"fresh", "current-source", "fresh", "current-source"}
	if len(calls) != len(want) {
		t.Fatal(calls)
	}
	for i := range want {
		if calls[i] != want[i] {
			t.Fatal(calls)
		}
	}
}
func TestCheckerSourceAuthorityFailureAndCancellationNeverReadSource(t *testing.T) {
	denied := errors.New("current authority denied")
	for _, cancelAfter := range []bool{false, true} {
		ctx, cancel := context.WithCancel(context.Background())
		reads := 0
		check := checkerSourceAuthorizer(func(context.Context) error {
			if cancelAfter {
				cancel()
				return nil
			}
			return denied
		}, func(context.Context) error { reads++; return nil })
		err := check(ctx)
		cancel()
		if reads != 0 || cancelAfter && !errors.Is(err, context.Canceled) || !cancelAfter && !errors.Is(err, denied) {
			t.Fatal(reads, err)
		}
	}
}
func TestCheckerSourceCurrentPolicyRejectsResultWithoutCachedGrant(t *testing.T) {
	denied := errors.New("source no longer allowed")
	fresh, reads := 0, 0
	check := checkerSourceAuthorizer(func(context.Context) error { fresh++; return nil }, func(context.Context) error {
		reads++
		if reads == 2 {
			return denied
		}
		return nil
	})
	if err := check(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := check(context.Background()); !errors.Is(err, denied) || fresh != 2 || reads != 2 {
		t.Fatal("final current source check reused permission", fresh, reads, err)
	}
}
