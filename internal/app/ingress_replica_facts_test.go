// SPDX-License-Identifier: Apache-2.0

package app

import (
	"reflect"
	"testing"

	"github.com/jay94ks/mydcd/internal/deployment"
	"github.com/jay94ks/mydcd/internal/ingress"
)

func TestIngressReplicaFactsExcludeFixedAndForeignRuntimeBackends(t *testing.T) {
	first, second := "workload/task/tenant/app/web/node-a/r1", "workload/task/tenant/app/web/node-a/r2"
	goal := deployment.GoalCommand{Follow: []string{first, second}}
	observation := ingress.Observation{Ready: true, Started: true, Backends: []ingress.BackendObservation{
		{Task: "workload/task/tenant/app/admin", Generation: 11, Revision: 11},
		{Task: first, Generation: 12, Revision: 13},
		{Task: second, Generation: 14, Revision: 15},
		{Task: "workload/task/other/app/web/node-a/r1", Generation: 16, Revision: 16},
	}}
	want := []deployment.ObjectRef{{Key: first, Generation: 12, Revision: 13}, {Key: second, Generation: 14, Revision: 15}}
	got, drained := ingressReplicaFacts(goal, deployment.Execution{}, observation)
	if !reflect.DeepEqual(got, want) || len(drained) != 0 {
		t.Fatal("runtime observation exceeded original replica identity", got, drained)
	}
	got[0].Revision++
	if observation.Backends[1].Revision != 13 {
		t.Fatal("producer result aliases runtime observation")
	}
	observation.Ready = false
	if got, _ := ingressReplicaFacts(goal, deployment.Execution{}, observation); len(got) != 0 {
		t.Fatal("unready listener published ready replica facts", got)
	}
	observation.Ready = true
	if got, drained := ingressReplicaFacts(deployment.GoalCommand{}, deployment.Execution{}, observation); len(got) != 0 || len(drained) != 0 {
		t.Fatal("fixed-only listener manufactured replica transition", got, drained)
	}
}
