// SPDX-License-Identifier: Apache-2.0

package lifecycle

import "testing"

func TestSourceActivityKeepsBusyIOAndUncertaintySeparateFromCachedBytes(t *testing.T) {
	store := &SourceStore{busy: map[string]int{"original": 2}, entries: map[string]SourceFact{"cached": {}}}
	activity, err := store.Activity()
	if err != nil || activity.CDJobs != 2 {
		t.Fatal(activity, err)
	}
	store.mu.Lock()
	activity, err = store.Activity()
	store.mu.Unlock()
	if err != nil || activity.Empty() {
		t.Fatal("busy original became empty", activity, err)
	}
	delete(store.busy, "original")
	activity, err = store.Activity()
	if err != nil || !activity.Empty() {
		t.Fatal("idle cached bytes treated as running IO", activity, err)
	}
	store.uncertain = true
	if _, err := store.Activity(); err == nil {
		t.Fatal("uncertain source publication became an empty census")
	}
}

func TestTenantSourceActivityDoesNotRetireAnotherTenantsBusyRead(t *testing.T) {
	store := &SourceStore{busy: map[string]int{"first/source": 2, "other/source": 3}}
	first, err := store.TenantActivity("first")
	if err != nil || first.CDJobs != 2 {
		t.Fatal(first, err)
	}
	absent, err := store.TenantActivity("absent")
	if err != nil || !absent.Empty() {
		t.Fatal("foreign busy read entered tenant census", absent, err)
	}
	all, err := store.Activity()
	if err != nil || all.CDJobs != 5 {
		t.Fatal("node census lost original reads", all, err)
	}
	store.uncertain = true
	if _, err := store.TenantActivity("absent"); err == nil {
		t.Fatal("uncertain owner became positive closure")
	}
}
