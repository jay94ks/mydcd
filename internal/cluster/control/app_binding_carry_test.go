// SPDX-License-Identifier: Apache-2.0

package control

import (
	"testing"

	"github.com/jay94ks/seafield/internal/cluster/state"
	"github.com/jay94ks/seafield/internal/deployment"
)

// A same-generation Task update keeps its binding only for the exact same
// needs and inputs; anything else reserves a binding of its own.
func TestSameGenerationTaskUpdateCarriesItsBinding(t *testing.T) {
	f := deliveryControlFixture(t)
	const app = "source-app"
	managedDNSTaskCoreSubmit(t, f, app, deployment.ResourceKey("network-ref", "tenant", app, "lan/node-a"), true, state.Applied)
	applyDNSCoreReport(t, f, managedDNSCoreReport(t, f, f.node), state.Applied)
	task := deployment.ResourceKey("task", "tenant", app, "web")
	managedDNSTaskCoreSubmit(t, f, app, task, true, state.Applied)
	managedDNSTaskCoreProgress(t, f, app, "bind-inputs", task, nil)
	a, err := f.p.Apps(f.s)
	if err != nil || len(a.bindings.Live()) != 1 {
		t.Fatal("original live binding", err)
	}
	b := a.bindings.Live()[0]
	original, _ := a.BindingSource(b.Digest())
	next := original
	next.Task.Revision++
	if at := carriedBinding(a, next, b.Needs()); at < 0 || a.sources[at].Digest != b.Digest() {
		t.Fatal("same-generation update lost its binding")
	}
	for label, change := range map[string]func(*AppBindingSource, *deployment.Needs){
		"same position":  func(s *AppBindingSource, _ *deployment.Needs) { s.Task.Revision = original.Task.Revision },
		"new generation": func(s *AppBindingSource, _ *deployment.Needs) { s.Task.Generation++ },
		"other inputs":   func(s *AppBindingSource, _ *deployment.Needs) { s.Inputs.Revision++ },
		"other needs":    func(_ *AppBindingSource, n *deployment.Needs) { n.Consumer += "-other" },
	} {
		source, needs := next, b.Needs()
		change(&source, &needs)
		if carriedBinding(a, source, needs) >= 0 {
			t.Fatal("binding carried across a real change:", label)
		}
	}
}
