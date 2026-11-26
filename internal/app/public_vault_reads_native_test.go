// SPDX-License-Identifier: Apache-2.0

package app

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"reflect"
	"slices"
	"testing"

	"github.com/jay94ks/mydcd/internal/access"
	"github.com/jay94ks/mydcd/internal/cluster"
	"github.com/jay94ks/mydcd/internal/cluster/control"
	"github.com/jay94ks/mydcd/internal/mydcp"
	"github.com/jay94ks/mydcd/internal/secrets"
	"github.com/jay94ks/mydcd/internal/userauth"
)

// These checks extend the original ordered Secret/Group fixture, including its
// actual user approval, source revoke, native down and retirement. There is no
// second app/provider, synthetic grant or substitute closure observation.
type managedVaultReadChecks struct {
	original []secrets.PublicApproval
	page     func(*testing.T, context.Context) []secrets.PublicApproval
	usages   func(*testing.T, context.Context, int)
}

func captureManagedVaultReads(t *testing.T, ctx context.Context, root string, user userauth.Client, peer mydcp.Peer, session access.Session, p control.Policy, read func() cluster.View, grants []secrets.Grant) *managedVaultReadChecks {
	t.Helper()
	checks := &managedVaultReadChecks{}
	checks.page = func(t *testing.T, ctx context.Context) []secrets.PublicApproval {
		t.Helper()
		query := control.PublicReadQuery{App: "app"}
		page := readNativePublicPage(t, ctx, user, peer, session, "vault-approvals", "tenant", query)
		cli := nativePublicCLI(t, ctx, root, "vault-approvals", "tenant", query)
		vault, err := p.Vault(read().State)
		if err != nil {
			t.Fatal(err)
		}
		var rows []secrets.PublicApproval
		for _, row := range page.Rows {
			if row.Approval == nil || row.Approval.Realm != "tenant" || row.Approval.Tenant != "tenant" || row.Approval.App != "app" {
				t.Fatal("actual approval page exposed foreign realm or unrelated metadata", row)
			}
			rows = append(rows, *row.Approval)
		}
		if page.Total != len(rows) || cli.Total != page.Total || !sameSecretUsages(cli.Rows, page.Rows) || !reflect.DeepEqual(rows, vault.Approvals.PublicApprovals(vault.Trees["tenant"], "app")) {
			t.Fatal("user/CLI approval reads differ from original revoke/retire book", page, cli)
		}
		raw, err := json.Marshal(rows)
		if err != nil {
			t.Fatal(err)
		}
		for _, private := range []string{"Signature", "RequesterKey", "NodeKey", "Password", "Verifier", "Reference", "private-native-group-password", "private-db-value"} {
			if bytes.Contains(raw, []byte(private)) {
				t.Fatal("private input exposed by actual approval read", private)
			}
		}
		// This fixture has no other tenant/tree. Rejection must not fall back
		// to the current tenant's records. Populated same-name realm isolation
		// is covered by the shared-book core test.
		foreign, err := user.PublicRead(ctx, peer, session, "vault-approvals", "other", query, "")
		if err == nil || foreign.PublicRead != nil && len(foreign.PublicRead.Rows) != 0 {
			t.Fatal("missing foreign realm disclosed own approval rows", foreign, err)
		}
		return rows
	}
	checks.usages = func(t *testing.T, ctx context.Context, want int) {
		t.Helper()
		vault, err := p.Vault(read().State)
		if err != nil {
			t.Fatal(err)
		}
		for _, name := range []string{"base", "common"} {
			query := control.PublicReadQuery{Name: name}
			page := readNativePublicPage(t, ctx, user, peer, session, "vault-usages", "tenant", query)
			cli := nativePublicCLI(t, ctx, root, "vault-usages", "tenant", query)
			var rows []secrets.PublicUsage
			for _, row := range page.Rows {
				if row.SecretUsage == nil {
					t.Fatal("actual source usage returned unrelated metadata", row)
				}
				rows = append(rows, *row.SecretUsage)
			}
			core := vault.Approvals.PublicUsages(vault.Trees["tenant"], name)
			object, _ := vault.Trees["tenant"].Object(name)
			if len(rows) != want || page.Total != want || cli.Total != want || !sameSecretUsages(cli.Rows, page.Rows) || !slices.EqualFunc(rows, core, func(a, b secrets.PublicUsage) bool { return reflect.DeepEqual(a, b) }) || vault.Approvals.LiveReferences(vault.Trees["tenant"], name, object.Generation) != want {
				t.Fatal("actual User/CLI usage differs from original retirement fence", name, page, cli)
			}
			for _, row := range rows {
				if row.Realm != "tenant" || row.Tenant != "tenant" || row.App != "app" || row.User != session.User || row.Service != "web" || row.Node != "node-a" || !row.Live || row.Deployment != grants[0].Use.Deployment || len(row.Secrets) == 0 {
					t.Fatal("actual ordered Group/leaf usage lost original consumer", row)
				}
			}
		}
	}
	rows := checks.page(t, ctx)
	ids := map[string]bool{}
	for _, grant := range grants {
		for _, pin := range grant.Pins {
			ids[pin.ApprovalID] = true
		}
	}
	// Provider preparation and the actual CLI requester may have distinct
	// valid approvals for the same user/app. The list must keep both; only
	// the two pins in this original accepted grant have this native consumer.
	for _, row := range rows {
		if ids[row.ID] {
			checks.original = append(checks.original, row)
		} else if row.Consumers != 0 {
			t.Fatal("unrelated preparatory approval acquired the actual app consumer", row)
		}
	}
	if len(checks.original) != len(ids) || len(ids) != 2 {
		t.Fatal("approval listing does not identify both original accepted Group grants", checks.original)
	}
	vault, err := p.Vault(read().State)
	if err != nil {
		t.Fatal(err)
	}
	for _, row := range checks.original {
		group, ok := vault.Trees["tenant"].Object(row.Group)
		expires := int64(0)
		if group.MaxApprovalAge > 0 {
			expires = row.ApprovedAt + group.MaxApprovalAge
		}
		if !ok || !ids[row.ID] || row.User != session.User || row.Deployment != grants[0].Use.Deployment || row.ApprovedAt <= 0 || row.ExpiresAt != expires || row.Issuer == ([32]byte{}) || row.Revoking || row.Consumers != 1 || !slices.Equal(row.Services, []string{"web"}) || !slices.Equal(row.Nodes, []string{"node-a"}) {
			t.Fatal("actual approval row lost signed target/current age", row)
		}
	}
	checks.usages(t, ctx, 1)
	return checks
}

func (checks *managedVaultReadChecks) assert(t *testing.T, ctx context.Context, consumers int, revoked map[string]bool) {
	t.Helper()
	if checks == nil || len(checks.original) != 2 {
		t.Fatal("original ordered Group approval read hook missing")
	}
	rows := checks.page(t, ctx)
	for _, original := range checks.original {
		index := slices.IndexFunc(rows, func(row secrets.PublicApproval) bool { return row.ID == original.ID })
		if index < 0 {
			if revoked[original.ID] && consumers == 0 {
				continue // REQ42 permits a revoked, fully returned row to disappear.
			}
			t.Fatal("original approval disappeared before explicit revoke/closure", original.ID)
		}
		row := rows[index]
		want := original
		want.Consumers, want.Revoking = consumers, revoked[original.ID]
		if !reflect.DeepEqual(row, want) {
			t.Fatal("approval read changed original identity or source revoke impersonated approval revoke", row, want)
		}
	}
}

func finishManagedVaultApprovalReads(t *testing.T, ctx context.Context, p control.Policy, read func() cluster.View, change func(string, string, uint64, any), checks *managedVaultReadChecks) {
	t.Helper()
	// Called only after the original native down and source retire. Source
	// revocation is not approval-specific revocation and must not stand in
	// for the latter acceptance condition.
	checks.assert(t, ctx, 0, nil)
	revoked := map[string]bool{}
	for i, original := range checks.original {
		vault, err := p.Vault(read().State)
		if err != nil {
			t.Fatal(err)
		}
		change(fmt.Sprintf("ordered-revoke-approval-%d", i), "vault-revoke-approval", vault.Approvals.Revision(), control.VaultApprovalSelection{ID: original.ID})
		revoked[original.ID] = true
		checks.assert(t, ctx, 0, revoked)
	}
}

// The CLI prints the usages, not the page rows' keys.
func sameSecretUsages(a, b []control.PublicReadRow) bool {
	return slices.EqualFunc(a, b, func(x, y control.PublicReadRow) bool { return reflect.DeepEqual(x.SecretUsage, y.SecretUsage) })
}
