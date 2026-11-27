// SPDX-License-Identifier: Apache-2.0

//go:build linux

package app

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/jay94ks/seafield/internal/cluster"
	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/cluster/state"
)

// Uses the existing installed Vault/private HTTPS/CLI/Raft/reader and owned
// rollback setup. The finite selector stops before any app/native image load,
// Git, builder or large-context scenario. In-use and uncertain remote DELETE
// recovery remain the existing control/SDK counterexamples, not claims here.
func TestRQ6ExternalRegistryMaintenanceCLIOriginalHTTPOutcomeAndReaderReturn(t *testing.T) {
	if os.Getenv("SFC_TEST_RQ6_REMAINING") != "external-maintenance" {
		t.Skip("explicit external-maintenance remaining scope required")
	}
	runManagedAppOwner(t, true, true, true, true, managedAppExternalRegistry, true)
}

func (f *externalRegistryAppNative) verifyExternalRegistryMaintenanceNative(t *testing.T, ctx context.Context, owner *Runtime, p control.Policy, read func() cluster.View, change func(string, string, uint64, any)) {
	t.Helper()
	type completed struct {
		args  []string
		row   control.RegistryMaintenanceRecord
		repo  string
		code  string
		state string
	}
	var originals []completed
	seen := map[string]bool{}
	status := func(id, state, code string) control.RegistryMaintenanceRecord {
		t.Helper()
		var original control.RegistryMaintenanceRecord
		registryNativeWait(t, ctx, "original external maintenance "+id, func() bool {
			jobs, err := p.RegistryMaintenanceJobs(read().State)
			if err != nil {
				t.Fatal(err)
			}
			var found bool
			original, found = jobs.Record(id)
			return found && !original.Pending()
		})
		output, diagnostic, err := f.cli.runCLI(nil, "registry", "maintenance-status", id, "--tenant", "tenant")
		f.publicBytes(t, "external maintenance status", output)
		f.publicBytes(t, "external maintenance diagnostic", diagnostic)
		if state == "done" {
			if err != nil {
				t.Fatal("successful external maintenance status", err)
			}
		} else {
			var exit interface{ ExitCode() int }
			if !errors.As(err, &exit) || exit.ExitCode() != 3 {
				t.Fatal("known external refusal did not preserve its failed outcome", err)
			}
		}
		var public control.RegistryMaintenanceStatus
		if json.Unmarshal(output, &public) != nil || public.Operation != id || public.Action != "delete-registry-image" || public.Tenant != "tenant" || public.State != state || public.Result == nil || public.Result.Code != code || original.State != state || original.Result == nil || !reflect.DeepEqual(public.Result, original.Result) || public.Change.DigestValue() != original.Change.DigestValue() || public.Revision != original.Revision {
			t.Fatal("public external maintenance lost original target/outcome", id, code)
		}
		return original
	}
	noReferences := func() {
		t.Helper()
		refs, err := p.ImageReferences(read().State, "tenant", "")
		if err != nil {
			t.Fatal(err)
		}
		for _, row := range refs {
			for _, repository := range []string{"fixture", "second", "unsupported"} {
				if row.MatchImage(f.remote.PrivateReference(repository)) != "" {
					t.Fatal("finite unused external seed acquired an app/build usage")
				}
			}
		}
	}
	noReferences()
	for _, selected := range []struct{ source, repository, id, state, code string }{
		{"external-app", "fixture", "rq6-external-delete-original", "done", "OK"},
		{"external-second", "second", "rq6-external-delete-denied", "failed", "DENIED"},
		{"external-unsupported", "unsupported", "rq6-external-delete-unsupported", "failed", "UNSUPPORTED"},
	} {
		pinned := f.remote.PrivateReference(selected.repository)
		_, digest, found := strings.Cut(pinned, "@")
		if !found || seen[digest] {
			t.Fatal("external maintenance requires distinct actual owned seed digests")
		}
		seen[digest] = true
		imageQueryResolveNative(t, f.cli, "tenant", pinned, "external", selected.source, "OK", pinned, f.publicBytes)
		args := []string{"registry", "delete-image", selected.source, "--external", "--tenant", "tenant", "--repository", selected.repository, "--reference", digest, "--expected-digest", digest}
		body := f.cli.cli(nil, append(append([]string(nil), args...), "--preview")...)
		f.publicBytes(t, "external delete preview", body)
		var plan control.RegistryMaintenancePlan
		if json.Unmarshal(body, &plan) != nil || plan.Schema != 1 || plan.Cluster != p.Cluster || plan.Tenant != "tenant" || plan.Action != "delete-registry-image" || plan.InUse || plan.Change.Operation != "" || plan.Change.External == nil || plan.Change.RegistryID() != selected.source || plan.Change.Authority() != f.remote.Registry || plan.Change.Repository != selected.repository || plan.Change.Reference != digest || plan.Change.Digest != digest || plan.Change.OwnerKey() != owner.Identity.Public || plan.Expected != plan.Change.ExpectedRevision() {
			t.Fatal("actual typed external preview lost exact source/authority/repository/digest")
		}
		matched := false
		for _, reader := range f.readers {
			if reader.Spec.ID == selected.source {
				matched = plan.Change.External.Selection.Generation == reader.Generation && plan.Change.External.Owner == reader.Owner && plan.Change.External.ReadSet != ([32]byte{}) && plan.Change.External.Selection.Tenant == reader.Spec.Tenant
			}
		}
		if !matched {
			t.Fatal("external preview did not pin the original approved reader")
		}
		if attempts, deleted := f.remote.PrivateDeleteStats(selected.repository); attempts != 0 || deleted {
			t.Fatal("read-only preview changed native remote content")
		}
		args = append(args, "--request-id", selected.id)
		output := f.cli.cli(nil, args...)
		f.publicBytes(t, "external delete acceptance", output)
		var acceptance struct {
			Status, Operation string
			External          bool
			Result            *state.Result
		}
		if json.Unmarshal(output, &acceptance) != nil || acceptance.Status != "accepted" || acceptance.Operation != selected.id || !acceptance.External || acceptance.Result == nil || acceptance.Result.Code != state.Applied {
			t.Fatal("external delete did not accept its original typed User operation")
		}
		original := status(selected.id, selected.state, selected.code)
		expected := plan.Change
		expected.Operation = selected.id
		if original.Origin.VerifyOriginal(p.Cluster) != nil || original.Origin.RequestID != selected.id || original.Change.DigestValue() != expected.DigestValue() || original.Result.Native == ([32]byte{}) || original.Result.ReclaimedBytes != 0 {
			t.Fatal("external terminal outcome changed the signed source/target or invented reclaimed bytes")
		}
		local, err := owner.loadRegistryMaintenance(control.RegistryMaintenanceWork{Operation: selected.id, Change: original.Change})
		if err != nil || !local.Sent || local.Owner != owner.Identity.Public || local.Target != original.Change.DigestValue() || !reflect.DeepEqual(local.Result, original.Result) {
			t.Fatal("original external HTTP outcome missing from actual owner receipt", err)
		}
		if attempts, deleted := f.remote.PrivateDeleteStats(selected.repository); attempts != 1 || deleted != (selected.code == "OK") {
			t.Fatal("original external HTTP DELETE attempt/effect differs from terminal outcome", selected.code, attempts, deleted)
		}
		before, _ := f.remote.PrivateStats(selected.repository)
		if selected.code == "OK" {
			// These are real authenticated SDK GETs through CLI/User/Runtime,
			// independently of the DELETE response and its retained result.
			imageQueryResolveNative(t, f.cli, "tenant", pinned, "external", selected.source, "NOT_FOUND", "", f.publicBytes)
			imageQueryResolveNative(t, f.cli, "tenant", f.remote.Registry+"/"+selected.repository+":owned", "external", selected.source, "NOT_FOUND", "", f.publicBytes)
			var images control.RegistryCatalogueResult
			body := f.cli.cli(nil, "registry", "images", selected.source, "--external", "--repository", selected.repository, "--tenant", "tenant")
			f.publicBytes(t, "external tags after native delete", body)
			if json.Unmarshal(body, &images) != nil || !images.ValidQuery(control.RegistryCatalogueQuery{Kind: "external", ID: selected.source, Repository: selected.repository}, "") || images.Page.Code != "OK" || !images.Page.Live || images.Page.Authority != f.remote.Registry || len(images.Page.Images) != 0 {
				t.Fatal("native immutable deletion did not remove the original remote tag")
			}
		} else {
			imageQueryResolveNative(t, f.cli, "tenant", pinned, "external", selected.source, "OK", pinned, f.publicBytes)
		}
		if after, _ := f.remote.PrivateStats(selected.repository); after <= before {
			t.Fatal("native post-delete/refusal content check did not reach authenticated HTTP")
		}
		// Original intent/result recovery must neither create a second operation
		// nor issue DELETE again, including known failed HTTP outcomes.
		f.cli.cli(nil, args...)
		again := status(selected.id, selected.state, selected.code)
		if again.Revision != original.Revision || !reflect.DeepEqual(again.Result, original.Result) || !bytes.Equal(control.OperationBytes(again.Origin), control.OperationBytes(original.Origin)) {
			t.Fatal("same external request ID changed its original result")
		}
		if attempts, _ := f.remote.PrivateDeleteStats(selected.repository); attempts != 1 {
			t.Fatal("original result lookup sent another external DELETE", attempts)
		}
		originals = append(originals, completed{args: args, row: original, repo: selected.repository, code: selected.code, state: selected.state})
	}
	noReferences()
	// Reuse the original source-reader drain/join and exact grant/UseGone checks.
	// No app was accepted in this finite scope; only its approved readers held
	// Secret usage. Revocation precedes retirement just as in the app fixture.
	f.cli.cli(nil, "--tenant", "tenant", "secret", "revoke", "--id", "registry-auth", "--request-id", "external-maintenance-revoke-secret")
	f.checkRetired(t, ctx, owner, p, read, change)
	for _, original := range originals {
		f.cli.cli(nil, original.args...)
		again := status(original.row.Change.Operation, original.state, original.code)
		if again.Revision != original.row.Revision || !reflect.DeepEqual(again.Result, original.row.Result) || !bytes.Equal(control.OperationBytes(again.Origin), control.OperationBytes(original.row.Origin)) {
			t.Fatal("reader closure erased original external maintenance evidence")
		}
		if attempts, _ := f.remote.PrivateDeleteStats(original.repo); attempts != 1 {
			t.Fatal("closed reader result lookup retried original DELETE")
		}
	}
	noReferences()
	f.public["ExternalMaintenanceOriginalHTTPDelete"] = originals[0].row.Change.Operation
	f.public["ExternalMaintenanceKnownHTTPRefusals"] = []string{"DENIED", "UNSUPPORTED"}
	f.public["ExternalMaintenanceNativeAbsenceAndOriginalResultNoRetry"], f.public["ExternalMaintenanceOriginalReadersReturned"] = true, true
	f.save()
}
