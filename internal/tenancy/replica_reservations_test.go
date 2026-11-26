// SPDX-License-Identifier: Apache-2.0

package tenancy

import (
	"testing"

	"github.com/jay94ks/mydcd/internal/workload"
)

func TestReplicaReservationsUseExactNodeAndCanonicalOrdinalWithinSharedQuota(t *testing.T) {
	f, q := quotaFixture(t)
	first := request("first", "web/node-a/r1", public(f.a), 2, 20)
	first.Generation, first.Revision = 10, 12
	second := first
	second.Key, second.Generation, second.Revision = "workload/task/first/app/web/node-a/r2", 13, 14
	n, err := q.WithCommittedReservations([]Reservation{first, second})
	if err != nil {
		t.Fatal("canonical replica reservations refused", err)
	}
	if used, err := n.Usage("first", "node-a"); err != nil || used != (workload.Resources{CPU: 4, Memory: 40}) {
		t.Fatal("replicas bypassed aggregate quota", used, err)
	}
	raw, err := n.Encode()
	if err != nil {
		t.Fatal(err)
	}
	restored, err := DecodeQuotas(raw)
	if err != nil {
		t.Fatal("replica source identity cannot recover", err)
	}
	if got, ok := restored.Reservation(second.Key); !ok || got != second {
		t.Fatal("replica source coordinates changed")
	}
	third := first
	third.Key = "workload/task/first/app/web/node-a/r3"
	if _, err := n.WithCommittedReservation(third); err == nil {
		t.Fatal("replica exceeded shared tenant capacity")
	}
	for _, key := range []string{
		"workload/task/first/app/web/node-b/r1",
		"workload/task/first/app/web/node-a/r0",
		"workload/task/first/app/web/node-a/r01",
		"workload/task/first/app/web/node-a/r129",
		"workload/task/first/app/web/node-a/1",
		"workload/registry/first/app/web/node-a/r1",
		"workload/task/second/app/web/node-a/r1",
	} {
		bad := first
		bad.Key = key
		if _, err := q.WithCommittedReservation(bad); err == nil {
			t.Fatal("invalid source accepted as a replica reservation", key)
		}
	}
	if used, err := q.Usage("first", "node-a"); err != nil || used != (workload.Resources{}) {
		t.Fatal("projection mutated original quotas")
	}
}
