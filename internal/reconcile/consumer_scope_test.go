// SPDX-License-Identifier: Apache-2.0

package reconcile

import (
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
)

func TestConsumerScopeIsAtomicImmutableAndPreservedWithOriginalPinsOnReopen(t *testing.T) {
	j, path, d, _ := admissionJournal(t, 4)
	original, _ := j.Read("bridge")
	raw, _ := json.Marshal(original)
	if strings.Contains(string(raw), "Scope") {
		t.Fatal("legacy schema1 encoding changed")
	}
	scope := ConsumerScope{Tenant: "first", Node: "node-a", Owner: "cluster/node-key"}
	pin, err := j.BorrowScoped("bridge", "original", 1, d.Revision, 2, scope)
	if err != nil {
		t.Fatal(err)
	}
	r, err := j.Read("bridge")
	if err != nil || r.Scope != scope || r.Consumers["original"] != pin {
		t.Fatal("scope and pin not committed together", r, err)
	}
	before := cloneRecord(r)
	other := scope
	other.Tenant = "second"
	if err := j.BindConsumerScope("bridge", d, other); !errors.Is(err, ErrLease) {
		t.Fatal("original scope rebound", err)
	}
	if _, err := j.BorrowScoped("bridge", "original", 1, d.Revision, 2, other); !errors.Is(err, ErrLease) {
		t.Fatal("scoped lookup crossed tenants", err)
	}
	if _, err := j.Borrow("bridge", "unscoped-new", 1); !errors.Is(err, ErrLease) {
		t.Fatal("legacy borrow bypassed scoped admission", err)
	}
	after, _ := j.Read("bridge")
	if !reflect.DeepEqual(before, after) {
		t.Fatal("rejected scope changes edited original metadata")
	}
	if err := j.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := OpenJournal(path)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	r, err = reopened.Read("bridge")
	if err != nil || r.Scope != scope || r.Consumers["original"] != pin {
		t.Fatal("scope/pin lost across actual DB reopen", r, err)
	}
	if same, err := reopened.Borrow("bridge", "original", 1); err != nil || same != pin {
		t.Fatal("legacy original recovery became fresh admission", same, err)
	}
	if err := reopened.Return("bridge", "original", pin); err != nil {
		t.Fatal(err)
	}
	r, _ = reopened.Read("bridge")
	if r.Scope != scope || r.Pins.Next != pin.Token {
		t.Fatal("return reset ownership or token floor")
	}
}

func TestConsumerScopeBindingRequiresTheExactUnchangedAdmittedSource(t *testing.T) {
	j, _, d, _ := admissionJournal(t, 4)
	pin, err := j.Borrow("bridge", "legacy-original", 1)
	if err != nil {
		t.Fatal(err)
	}
	scope := ConsumerScope{Tenant: "first", Node: "node-a", Owner: "cluster/node-key"}
	old := d
	d.Revision++
	if err := j.Desired("bridge", d, 4); err != nil {
		t.Fatal(err)
	}
	if err := j.BindConsumerScope("bridge", old, scope); !errors.Is(err, ErrLease) {
		t.Fatal("late permission mapped a changed source", err)
	}
	if err := j.BindConsumerScope("bridge", d, scope); err != nil {
		t.Fatal(err)
	}
	r, _ := j.Read("bridge")
	if r.Scope != scope || r.Consumers["legacy-original"] != pin || r.Pins.Next != pin.Token {
		t.Fatal("scope upgrade recreated legacy pins", r)
	}
	d.Revision++
	d.Resource.Spec = "another-native-source"
	d.Resource.Generation++
	if err := j.Desired("bridge", d, 4); err != nil {
		t.Fatal(err)
	}
	// Known original scope remains readable during a cold replacement; it is
	// not replaced by the current target or inferred from its new labels.
	if err := j.BindConsumerScope("bridge", d, ConsumerScope{Tenant: "second", Node: scope.Node, Owner: scope.Owner}); !errors.Is(err, ErrLease) {
		t.Fatal("cold target replaced original scope", err)
	}
}
