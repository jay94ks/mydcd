// SPDX-License-Identifier: Apache-2.0

package volumes

import (
	"context"
	"testing"
)

func TestMovePlanningWriterPreservesOriginalAndNeverBecomesColdProof(t *testing.T) {
	f := activationTest(t)
	s := f.open(t)
	defer func() { _ = s.Close() }()
	ctx := context.Background()
	f.http.exists = true
	if err := s.Activate(ctx, f.ref); err != nil {
		t.Fatal(err)
	}
	ready, err := f.native.Ready(ctx, f.ref.NativeKey, makeFixture(t).a)
	if err != nil {
		t.Fatal(err)
	}
	writer, err := s.PlanningWriter(ready)
	if err != nil || writer != f.ref {
		t.Fatal("original active recipe", writer, err)
	}
	if _, err = s.ColdSource(ctx, ready); err == nil {
		t.Fatal("planning read manufactured cold closure")
	}
	if err = s.Close(); err != nil {
		t.Fatal(err)
	}
	s = f.open(t)
	again, err := s.PlanningWriter(ready)
	if err != nil || again != writer {
		t.Fatal("same DB original recipe", err)
	}
	f.http.exitState = sourceExitFixture()
	if err = s.Retire(ctx, f.ref); err != nil {
		t.Fatal(err)
	}
	if _, err = s.PlanningWriter(ready); err == nil {
		t.Fatal("closed historical writer substituted for active source")
	}
	cold, err := s.ColdSource(ctx, ready)
	if err != nil || cold.Writer != writer || !cold.Exit.Clean() {
		t.Fatal("original recipe changed across real retirement", err)
	}
}
