// SPDX-License-Identifier: Apache-2.0

//go:build linux

package app

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"reflect"
	"slices"
	"testing"

	"github.com/jay94ks/mydcd/internal/access"
	"github.com/jay94ks/mydcd/internal/cluster"
	"github.com/jay94ks/mydcd/internal/cluster/control"
	"github.com/jay94ks/mydcd/internal/cluster/state"
	"github.com/jay94ks/mydcd/internal/identity"
	"github.com/jay94ks/mydcd/internal/imagebuild"
	"github.com/jay94ks/mydcd/internal/nodestorage"
	"github.com/jay94ks/mydcd/internal/userauth"
)

// The existing RQ6 CLI/Runtime/Raft fixture owns the wallet, registered ext4
// root and rollback. This adds no node, storage root or native process.
func (f *managedRegistryNative) verifyTenantStorageNative(t *testing.T, ctx context.Context, root string, selected nodestorage.Reference, p control.Policy, read func() cluster.View, change func(string, string, uint64, any)) {
	t.Helper()
	if err := ctx.Err(); err != nil {
		t.Fatal(err)
	}
	var admin userauth.Reply
	if err := json.Unmarshal(f.cli(nil, "whoami"), &admin); err != nil || admin.User == nil || !admin.User.SystemAdmin {
		t.Fatal("original admin wallet selection missing", err)
	}
	const username = "rq6-storage-manager"
	keyDir := filepath.Join(root, username)
	key, err := identity.Create(keyDir)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(key.Private)
	account := access.User{ID: username, Username: username, Enabled: true, Credentials: []access.Credential{{ID: "key", Method: access.PrivateKey, PublicKey: key.Public, Enabled: true}}}
	change("rq6-storage-user", "put-user", 0, account)
	change("rq6-storage-member", "set-membership", 0, access.Membership{Tenant: "tenant", User: username, Role: access.Manager, Enabled: true})
	const foreign = "rq6-storage-other"
	change("rq6-storage-foreign", "create-tenant", 0, control.TenantID{ID: foreign})
	login := func() {
		t.Helper()
		f.cli(nil, "--user", username, "login", "--method", "private-key", "--key-file", filepath.Join(keyDir, "key.pem"))
		var who userauth.Reply
		if err := json.Unmarshal(f.cli(nil, "--user", username, "whoami"), &who); err != nil || who.User == nil || who.User.ID != username || who.User.SystemAdmin {
			t.Fatal("ordinary tenant manager login missing", err)
		}
	}
	login()
	loggedIn := true
	defer func() {
		if loggedIn {
			if _, _, err := f.runCLI(nil, "--user", username, "logout"); err != nil {
				t.Error("original tenant storage login logout did not settle", err)
			}
		}
	}()
	denied := func(args ...string) {
		t.Helper()
		output, diagnostic, err := f.runCLI(nil, append([]string{"--user", username}, args...)...)
		var exit interface{ ExitCode() int }
		var receipt struct{ Result *state.Result }
		_ = json.Unmarshal(output, &receipt)
		if !errors.As(err, &exit) || exit.ExitCode() != 3 || receipt.Result != nil && receipt.Result.Code != state.Forbidden || receipt.Result == nil && !bytes.Contains(diagnostic, []byte("denied")) {
			t.Fatal("expected current tenant storage authorization refusal", args, err, string(diagnostic))
		}
	}
	list := func(node string) map[string]control.TenantStorageRoot {
		t.Helper()
		rows := map[string]control.TenantStorageRoot{}
		after := ""
		var index, revision, rootRevision uint64
		for {
			args := []string{"--user", username, "--tenant", "tenant", "manage", "tenant-storage"}
			if node != "" {
				args = append(args, "--node", node)
			}
			if after != "" {
				args = append(args, "--after", after)
			}
			var page userauth.Reply
			if err := json.Unmarshal(f.cli(nil, args...), &page); err != nil || page.TenantStorageViewIndex == 0 || len(page.TenantStorage) > 8 {
				t.Fatal("actual tenant storage CLI page missing", err)
			}
			if after != "" && (page.TenantStorageViewIndex < index || page.NodeStorageRevision != revision || page.NodeStorageRootRevision != rootRevision) {
				t.Fatal("tenant root pages mixed storage revisions")
			}
			index, revision, rootRevision = page.TenantStorageViewIndex, page.NodeStorageRevision, page.NodeStorageRootRevision
			for _, row := range page.TenantStorage {
				id := row.Node + "/" + row.ID
				if _, duplicate := rows[id]; duplicate || !row.Allowed || row.Root.Validate() != nil || row.Root.Cluster != p.Cluster || row.Root.Node != row.Node || row.Root.ID != row.ID || row.Root.Generation != row.Generation || node != "" && row.Node != node {
					t.Fatal("tenant root page lost complete reference or node filter", id)
				}
				rows[id] = row
			}
			if page.TenantStorageNext == "" {
				return rows
			}
			if len(page.TenantStorage) == 0 || page.TenantStorageNext == after || len(rows) > 1024 {
				t.Fatal("tenant root cursor did not advance")
			}
			after = page.TenantStorageNext
		}
	}
	all, filtered := list(""), list(selected.Node)
	row, ok := filtered[selected.Node+"/"+selected.ID]
	if !ok || row.Root != selected || row.Draining || !reflect.DeepEqual(all[selected.Node+"/"+selected.ID], row) {
		t.Fatal("manager did not discover the existing attested build root")
	}
	roots, err := p.NodeStorage(read().State)
	if err != nil {
		t.Fatal(err)
	}
	for id, candidate := range all {
		registered, ok := roots.Root(candidate.Node, candidate.ID)
		if !ok || registered.Reference(p.Cluster) != candidate.Root || !slices.Contains(registered.Definition.Tenants, "tenant") {
			t.Fatal("tenant list exposed another root or fabricated reference", id)
		}
		if candidate.Node == selected.Node && !reflect.DeepEqual(candidate, filtered[id]) {
			t.Fatal("node filter lost allowed root", id)
		}
	}
	denied("--tenant", foreign, "manage", "tenant-storage", "--node", selected.Node)
	denied("node", "storage", "list", selected.Node)

	policy := func() control.ImageBuildPolicyRecord {
		t.Helper()
		book, err := p.ImageBuilds(read().State)
		if err != nil {
			t.Fatal(err)
		}
		value, ok := book.Policy("tenant")
		if !ok || value.Deleted {
			t.Fatal("original build policy missing")
		}
		return value
	}
	original := policy()
	restoreNeeded := true
	defer func() {
		if restoreNeeded {
			current := policy()
			if !reflect.DeepEqual(current.Spec, original.Spec) {
				change("rq6-storage-restore-policy", "set-image-build-policy", current.Revision, control.ImageBuildPolicyPut{Spec: original.Spec.Own()})
			}
		}
	}()
	spec := original.Spec.Own()
	for i := range spec.Nodes {
		if spec.Nodes[i].Node == selected.Node {
			spec.Nodes[i].Root = row.Root
		}
	}
	// Make the real manager save observable, then restore every original field
	// by exact current CAS before the large upload acquires its policy scope.
	if spec.Seconds < 86400 {
		spec.Seconds++
	} else {
		spec.Seconds--
	}
	apply := func(id string, value imagebuild.Policy, reject bool) {
		t.Helper()
		payload, err := json.Marshal(control.ImageBuildPolicyPut{Spec: value})
		if err != nil {
			t.Fatal(err)
		}
		path := imageBuildNativeJSON(t, root, id, control.ChangeDocument{Schema: 1, Action: "set-image-build-policy", Expected: policy().Revision, Payload: payload})
		args := []string{"--tenant", "tenant", "manage", "apply", "--change", path, "--request-id", id}
		if reject {
			denied(args...)
		} else {
			f.cli(nil, append([]string{"--user", username}, args...)...)
		}
	}
	apply("rq6-storage-manager-policy", spec, false)
	saved := policy()
	if saved.Revision != original.Revision+1 || saved.Origin.Session.User != username || saved.Origin.Change.Expected != original.Revision || !reflect.DeepEqual(saved.Spec, spec) {
		t.Fatal("manager did not save discovered full reference through original signed CAS")
	}
	change("rq6-storage-restore-policy", "set-image-build-policy", saved.Revision, control.ImageBuildPolicyPut{Spec: original.Spec.Own()})
	restored := policy()
	if restored.Revision != saved.Revision+1 || !reflect.DeepEqual(restored.Spec, original.Spec) {
		t.Fatal("original admin build policy was not restored")
	}
	restoreNeeded = false
	membership := func() access.Membership {
		t.Helper()
		catalog, err := p.Catalog(read().State)
		if err != nil {
			t.Fatal(err)
		}
		member, ok := catalog.Membership("tenant", username)
		if !ok {
			t.Fatal("storage fixture membership missing")
		}
		return member
	}
	change("rq6-storage-viewer", "set-membership", membership().Revision, access.Membership{Tenant: "tenant", User: username, Role: access.Viewer, Enabled: true})
	denied("--tenant", "tenant", "manage", "tenant-storage", "--node", selected.Node)
	apply("rq6-storage-viewer-policy", spec, true)
	change("rq6-storage-manager-again", "set-membership", membership().Revision, access.Membership{Tenant: "tenant", User: username, Role: access.Manager, Enabled: true})
	if list(selected.Node)[selected.Node+"/"+selected.ID].Root != selected {
		t.Fatal("current restored manager cannot read its root")
	}
	catalog, err := p.Catalog(read().State)
	if err != nil {
		t.Fatal(err)
	}
	current, ok := catalog.User(username)
	if !ok || current.SystemAdmin {
		t.Fatal("ordinary fixture account missing")
	}
	account.Credentials[0].Operations = []string{"revoke-session"}
	change("rq6-storage-key-ceiling", "put-user", current.Revision, account)
	login() // Account revision changed; do not mistake a stale session for a ceiling.
	if list(selected.Node)[selected.Node+"/"+selected.ID].Root != selected {
		t.Fatal("restricted credential lost ordinary read authorization")
	}
	apply("rq6-storage-ceiling-policy", spec, true)
	catalog, err = p.Catalog(read().State)
	if err != nil {
		t.Fatal(err)
	}
	current, ok = catalog.User(username)
	if !ok {
		t.Fatal("restricted account missing")
	}
	account.Credentials[0].Operations = nil
	change("rq6-storage-clear-key-ceiling", "put-user", current.Revision, account)
	login()
	if list(selected.Node)[selected.Node+"/"+selected.ID].Root != selected {
		t.Fatal("unrestricted manager precondition before membership revocation missing")
	}
	change("rq6-storage-revoke", "set-membership", membership().Revision, access.Membership{Tenant: "tenant", User: username, Role: access.Manager, Enabled: false})
	denied("--tenant", "tenant", "manage", "tenant-storage", "--node", selected.Node)
	apply("rq6-storage-revoked-policy", spec, true)
	if after := policy(); after.Revision != restored.Revision || !reflect.DeepEqual(after.Spec, original.Spec) {
		t.Fatal("refused user changes altered the original build policy")
	}
	f.cli(nil, "--user", username, "logout")
	loggedIn = false
	var final userauth.Reply
	if err := json.Unmarshal(f.cli(nil, "whoami"), &final); err != nil || final.User == nil || !reflect.DeepEqual(final.User, admin.User) {
		t.Fatal("manager logout changed original admin wallet selection", err)
	}
	f.public["TenantStorageManagerReference"], f.public["TenantStorageManagerPolicyCAS"] = selected, saved.Revision
	f.public["TenantStorageForeignViewerCeilingAndRevocationDenied"] = true
	f.save()
}
