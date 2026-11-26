// SPDX-License-Identifier: Apache-2.0

package deployment

import (
	"crypto/ed25519"
	"testing"
)

// An unchanged fact is renewed over MyDCP and never moves the Execution;
// only an outage (one expiry) and the owner's next fact are Raft writes.
func TestObservationRenewalExpiryAndRevival(t *testing.T) {
	x := runFixture(t)
	for _, step := range x.b.Steps() {
		x.completeStep(step.Key)
	}
	key := ResourceKey("task", "tenant", "php-mysql", "db")
	stage, _ := x.e.Stage(key)
	old := *stage.Observation
	sign := func(o Observation) Observation {
		k := x.f.na
		if o.Owner == public(x.f.nb) {
			k = x.f.nb
		}
		o.Signature = ed25519.Sign(k, ObservationBytes(o))
		return o
	}
	renewal := old
	renewal.Sequence++
	renewal.At += 20
	renewal = sign(renewal)
	if !ObservationRenews(old, renewal) || x.e.CheckRenewal(renewal, renewal.At) != nil {
		t.Fatal("unchanged fact was not a renewal")
	}
	changed := renewal
	changed.Healthy = !changed.Healthy
	changed = sign(changed)
	if ObservationRenews(old, changed) || x.e.CheckRenewal(changed, changed.At) == nil {
		t.Fatal("changed fact accepted as a renewal")
	}
	forged := renewal
	forged.Signature = append([]byte(nil), renewal.Signature...)
	forged.Signature[0] ^= 1
	if x.e.CheckRenewal(forged, forged.At) == nil {
		t.Fatal("unsigned renewal accepted")
	}
	if _, err := x.e.ExpireObservation(x.e.Revision(), key, old.Sequence, old.At+50, 50); err == nil {
		t.Fatal("expired within max age")
	}
	if _, err := x.e.ExpireObservation(x.e.Revision(), key, old.Sequence+1, old.At+51, 50); err == nil {
		t.Fatal("expired a newer observation")
	}
	before := x.e.Revision()
	expiredExecution, err := x.e.ExpireObservation(x.e.Revision(), key, old.Sequence, old.At+51, 50)
	if err != nil || expiredExecution.Revision() != before+1 || !progress(x.e, expiredExecution) {
		t.Fatal("expiry", err)
	}
	stage, _ = expiredExecution.Stage(key)
	if stage.Observation.Live(old.At+51) || expiredExecution.Health(old.At+51) != "Unknown" {
		t.Fatal("expired observation still live")
	}
	if expiredExecution.CheckRenewal(renewal, renewal.At) == nil {
		t.Fatal("expired observation renewed without a Raft fact")
	}
	if _, err := expiredExecution.Observe(expiredExecution.Revision(), renewal, renewal.At); err != nil {
		t.Fatal("owner fact did not revive the observation", err)
	}
	marked := renewal
	marked.Expired = true
	if _, err := expiredExecution.Observe(expiredExecution.Revision(), marked, marked.At); err == nil {
		t.Fatal("owner set the reducer's expiry mark")
	}
	if ObservationBytes(marked) == nil || string(ObservationBytes(marked)) != string(ObservationBytes(renewal)) {
		t.Fatal("expiry mark is signed")
	}
}
