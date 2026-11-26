// SPDX-License-Identifier: Apache-2.0

package volumes

import "testing"

func TestActivationCensusPreservesOriginalStartAndUnreturnedWriter(t *testing.T) {
	entry := &activationEntry{disk: activationRecord{Gate: GateCheckpoint{Starting: &Consumer{ID: "original"}}, Bindings: []activationBinding{{Ref: Activation{Consumer: Consumer{ID: "writer", Writable: true}}}, {Ref: Activation{Consumer: Consumer{ID: "reader"}}, Closed: true, Released: true}}}}
	store := &Activations{entries: map[string]*activationEntry{"original": entry}}
	activity, err := store.Activity()
	if err != nil || activity.Writers != 2 || activity.Leases != 0 || activity.Empty() {
		t.Fatal(activity, err)
	}
	entry.mu.Lock()
	activity, err = store.Activity()
	entry.mu.Unlock()
	if err != nil || activity.Empty() {
		t.Fatal("in-flight native lock became zero", activity, err)
	}
	entry.disk.Gate.Starting = nil
	entry.disk.Bindings[0].Closed, entry.disk.Bindings[0].Released = true, true
	activity, err = store.Activity()
	if err != nil || !activity.Empty() {
		t.Fatal("fully closed original not settled", activity, err)
	}
	store.closed = true
	if _, err = store.Activity(); err == nil {
		t.Fatal("closed owner was a fresh empty observation")
	}
}
