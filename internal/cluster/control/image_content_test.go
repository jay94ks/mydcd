// SPDX-License-Identifier: Apache-2.0

package control

import (
	"strings"
	"testing"

	"github.com/jay94ks/seafield/internal/access"
	"github.com/jay94ks/seafield/internal/cluster/state"
	"github.com/jay94ks/seafield/internal/registryclient"
)

func TestImageContentUsesCurrentTrustAndApprovedReaderWithoutCredentialDisclosure(t *testing.T) {
	f, _ := maintenanceSourceFixture(t)
	resolveTrust(t, f, []access.TrustRule{{Registry: "external.example", Repository: "team/app"}})
	q := registryclient.ContentQuery{Ref: "external.example/team/app@sha256:" + strings.Repeat("a", 64), Kind: "layer", Digest: "sha256:" + strings.Repeat("b", 64)}
	read, err := f.p.PlanImageContent(f.s, f.sessions["manager"], 3, "tenant", q, [32]byte{9})
	if err != nil || read.Resolve.Target.Code != "" || read.Resolve.Target.External == nil || read.Resolve.Target.ExternalReadSet == ([32]byte{}) {
		t.Fatal("approved content read", read, err)
	}
	if _, err = f.p.CurrentImageContent(f.s, read, 3); err != nil {
		t.Fatal(err)
	}
	if _, err = f.p.PlanImageContent(f.s, f.sessions["manager"], 3, "foreign", q, [32]byte{9}); err == nil {
		t.Fatal("foreign tenant content authority")
	}
	bad := q
	bad.Ref = "external.example/team/app:latest"
	if _, err = f.p.PlanImageContent(f.s, f.sessions["manager"], 3, "tenant", bad, [32]byte{9}); err == nil {
		t.Fatal("mutable content target")
	}
	f.apply("manager", "delete-external-registry", 2, RegistrySelection{Tenant: "tenant", ID: "private"}, state.Applied)
	if _, err = f.p.CurrentImageContent(f.s, read, 3); err == nil {
		t.Fatal("revoked source kept streaming")
	}
	fresh, err := f.p.PlanImageContent(f.s, f.sessions["manager"], 3, "tenant", q, [32]byte{9})
	if err != nil || fresh.Resolve.Target.Code != "SOURCE_REVOKED" || fresh.Resolve.Target.Kind != "external" {
		t.Fatal("revoked source became anonymous", fresh, err)
	}
}

func TestImageContentManagedTargetDoesNotSignPeriodicReadyObservation(t *testing.T) {
	f, spec := readyMaintenanceRegistry(t)
	resolveTrust(t, f, []access.TrustRule{{Registry: spec.Authority, Repository: "team/app"}})
	q := registryclient.ContentQuery{Ref: spec.Authority + "/team/app@sha256:" + strings.Repeat("a", 64), Kind: "manifest"}
	read, err := f.p.PlanImageContent(f.s, f.sessions["manager"], 3, "tenant", q, [32]byte{9})
	if err != nil || read.Resolve.Target.Managed == nil || read.Resolve.Target.Managed.Ready != nil || read.Resolve.Target.Code != "" {
		t.Fatal("periodic observation became content identity", read, err)
	}
}
