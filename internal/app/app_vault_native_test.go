// SPDX-License-Identifier: Apache-2.0

package app

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/jay94ks/seafield/internal/access"
	"github.com/jay94ks/seafield/internal/cluster"
	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/config"
	"github.com/jay94ks/seafield/internal/identity"
	"github.com/jay94ks/seafield/internal/reconcile"
	"github.com/jay94ks/seafield/internal/secrets"
	"github.com/jay94ks/seafield/internal/sfcp"
	"github.com/jay94ks/seafield/internal/userauth"
	"github.com/jay94ks/seafield/tests/vaultfixture"
)

func installManagedVault(t *testing.T, c *config.Node, root string, v *vaultfixture.Vault, lifetime ...time.Duration) {
	t.Helper()
	ttl := 5 * time.Minute
	if len(lifetime) > 1 {
		t.Fatal("one finite provider credential lifetime required")
	}
	if len(lifetime) == 1 {
		ttl = lifetime[0]
	}
	seconds := int((ttl + time.Second - 1) / time.Second)
	if seconds < 1 {
		t.Fatal("positive provider credential lifetime required")
	}
	v.API("PUT", "sys/policies/acl/sfc-native-app", map[string]any{"policy": `path "kv/data/tenant/*" { capabilities = ["create","update","read"] } path "kv/data/groups/tenant/*" { capabilities = ["create","update","read"] }`}, nil, v.Admin)
	var issued struct {
		Auth struct {
			Token   string `json:"client_token"`
			Seconds int    `json:"lease_duration"`
		} `json:"auth"`
	}
	v.API("POST", "auth/token/create", map[string]any{"policies": []string{"sfc-native-app"}, "no_default_policy": true, "ttl": fmt.Sprintf("%ds", seconds), "renewable": false}, &issued, v.Admin)
	if issued.Auth.Token == "" || issued.Auth.Seconds < seconds {
		t.Fatal("owned provider credential does not cover the finite scenario")
	}
	file := filepath.Join(root, "provider-token")
	if err := os.WriteFile(file, []byte(issued.Auth.Token), 0600); err != nil {
		t.Fatal(err)
	}
	for _, profile := range []string{"values", "auth"} {
		prefix := "tenant"
		if profile == "auth" {
			prefix = "groups/tenant"
		}
		c.Vaults = append(c.Vaults, config.VaultBackend{Realm: "tenant", Profile: profile, Address: v.Address, Mount: "kv", Prefix: prefix, CAFile: filepath.Join(v.Root, "tls.pem"), TokenFile: file, Values: profile == "values", Verifiers: profile == "auth"})
	}
}

func prepareManagedAppSecrets(t *testing.T, ctx context.Context, r *Runtime, user userauth.Client, peer sfcp.Peer, session access.Session, p control.Policy, read func() cluster.View, change func(string, string, uint64, any), consumers ...*Runtime) {
	consumer := r
	if len(consumers) > 0 {
		consumer = consumers[0]
	}
	prepareManagedAppSecretScenario(t, ctx, r, user, peer, session, p, read, change, consumer, managedAppOrdinary)
}
func prepareManagedAppSecretScenario(t *testing.T, ctx context.Context, r *Runtime, user userauth.Client, peer sfcp.Peer, session access.Session, p control.Policy, read func() cluster.View, change func(string, string, uint64, any), consumer *Runtime, scenario managedAppScenario) {
	t.Helper()
	ordered, localFiles := scenario == managedAppOrderedSecrets, scenario == managedAppLocalSecrets
	current := func() control.Vault {
		v, err := p.Vault(read().State)
		if err != nil {
			t.Fatal(err)
		}
		return v
	}
	change("vault-init", "vault-init", 0, control.VaultRealm{Realm: "tenant", Root: "root"})
	parent := "root"
	keys := []string{"DB_PASSWORD"}
	if ordered {
		for _, id := range []string{"common", "department"} {
			change("vault-create-"+id, "vault-create", current().Trees["tenant"].Revision(), control.VaultObject{Realm: "tenant", Object: secrets.Object{ID: id, Parent: "root", Kind: secrets.Group}})
		}
		parent, keys = "department", []string{"DATABASE", "DB_PASSWORD"}
		change("vault-base-data", "vault-create", current().Trees["tenant"].Revision(), control.VaultObject{Realm: "tenant", Object: secrets.Object{ID: "base", Parent: "common", Kind: secrets.Secret, Reference: secrets.Reference{Profile: "values", Object: "tenant/base", Keys: []string{"DB_PASSWORD", "DB_USER"}}}})
	}
	change("vault-group", "vault-create", current().Trees["tenant"].Revision(), control.VaultObject{Realm: "tenant", Object: secrets.Object{ID: "group", Parent: parent, Kind: secrets.Group}})
	var installedRevision uint64
	if localFiles {
		installedRevision = 1
	}
	change("vault-data", "vault-create", current().Trees["tenant"].Revision(), control.VaultObject{Realm: "tenant", Object: secrets.Object{ID: "data", Parent: "group", Kind: secrets.Secret, Reference: secrets.Reference{Profile: "values", Object: "tenant/data", Revision: installedRevision, Keys: keys}}})
	for _, profile := range []secrets.WriteProfile{{ID: "values", Node: r.installation.record.Root.Self.ID, Key: r.Identity.Public, Enabled: true, Values: true}, {ID: "auth", Node: r.installation.record.Root.Self.ID, Key: r.Identity.Public, Enabled: true, Verifiers: true}} {
		if localFiles && profile.ID == "values" {
			profile.Mode = "local-file"
		}
		change("vault-profile-"+profile.ID, "vault-set-profile", current().Trees["tenant"].Revision(), control.VaultProfile{Realm: "tenant", Profile: profile})
	}
	write := func(q secrets.WriteRequest, values map[string][]byte) {
		q.Epoch = current().Trees["tenant"].WriteEpoch()
		change(q.ID+"-prepare", "vault-prepare-write", current().Trees["tenant"].Revision(), control.VaultWrite{Realm: "tenant", Request: q})
		change(q.ID+"-dispatch", "vault-dispatch-write", current().Trees["tenant"].Revision(), control.VaultWriteAction{Realm: "tenant", ID: q.ID, Epoch: q.Epoch})
		reply, err := user.WriteVault(ctx, peer, session, userauth.SecretRequest{Realm: "tenant", ID: q.ID, Mode: "execute", Values: values})
		if err != nil || reply.VaultObservation == nil || reply.VaultObservation.Outcome != reconcile.EffectApplied {
			t.Fatal("real provider write", q.ID, err)
		}
		change(q.ID+"-observe", "vault-observe-write", current().Trees["tenant"].Revision(), control.VaultObserve{Observation: *reply.VaultObservation})
		record, _ := current().Trees["tenant"].Write(q.ID)
		change(q.ID+"-publish", "vault-publish-write", current().Trees["tenant"].Revision(), control.VaultWriteAction{Realm: "tenant", ID: q.ID, Epoch: q.Epoch, ObjectRevision: record.ExpectedObjectRevision})
	}
	values := map[string][]byte{"DB_PASSWORD": []byte("private-db-value")}
	if ordered {
		values["DATABASE"] = []byte("database-final")
		write(secrets.WriteRequest{ID: "base-write", Object: "base", Profile: "values", ProviderObject: "tenant/base", Kind: secrets.ValueWrite, Keys: []string{"DB_PASSWORD", "DB_USER"}}, map[string][]byte{"DB_PASSWORD": []byte("base-must-not-win"), "DB_USER": []byte("base-user")})
	}
	if !localFiles {
		write(secrets.WriteRequest{ID: "data-write", Object: "data", Profile: "values", ProviderObject: "tenant/data", Kind: secrets.ValueWrite, Keys: keys}, values)
	}
	password := []byte("private-native-group-password")
	defer clear(password)
	hash, err := identity.PasswordHash(password, bytes.Repeat([]byte{84}, 16), identity.DefaultPasswordCost())
	if err != nil {
		t.Fatal(err)
	}
	protected, err := hash.ProtectedBytes()
	if err != nil {
		t.Fatal(err)
	}
	defer clear(protected)
	group, _ := current().Trees["tenant"].Object("group")
	write(secrets.WriteRequest{ID: "group-password", Object: "group", Profile: "auth", ProviderObject: fmt.Sprintf("groups/tenant/group/%d", group.Generation), Kind: secrets.VerifierWrite, Protected: true}, map[string][]byte{"verifier": protected})
	if ordered {
		common, _ := current().Trees["tenant"].Object("common")
		write(secrets.WriteRequest{ID: "common-password", Object: "common", Profile: "auth", ProviderObject: fmt.Sprintf("groups/tenant/common/%d", common.Generation), Kind: secrets.VerifierWrite, Protected: true}, map[string][]byte{"verifier": protected})
	}
	change("approval-issuer", "vault-set-issuer", current().Approvals.Revision(), control.VaultIssuer{Key: r.Identity.Public, Enabled: true})
	uses := []secrets.Use{{Tenant: "tenant", User: "admin", App: "app", Deployment: "app", Service: "web", Node: "node-a", RequesterKey: session.Key, NodeKey: consumer.Identity.Public, Sources: []string{"data"}}}
	wantGroups := 1
	if ordered {
		uses[0].Sources = []string{"common", "department", "data"}
		wantGroups = 2
	}
	plan, err := user.PlanVaultApprovals(ctx, peer, session, "tenant", control.VaultApprovalPlanRequest{Realm: "tenant", ID: "native-first", Issuer: r.Identity.Public, Uses: uses})
	if err != nil || len(plan.Targets) != wantGroups {
		t.Fatal("first actual Group approval", err)
	}
	for _, target := range plan.Targets {
		if target.Existing != nil {
			t.Fatal("unexpected preexisting initial approval")
		}
		if _, err = user.ApproveVault(ctx, peer, session, target.Target, password); err != nil {
			t.Fatal("actual Group password/approval", err)
		}
	}
	reused, err := user.PlanVaultApprovals(ctx, peer, session, "tenant", control.VaultApprovalPlanRequest{Realm: "tenant", ID: "native-again", Issuer: r.Identity.Public, Uses: uses})
	if err != nil || len(reused.Targets) != wantGroups {
		t.Fatal("Group approval not reusable", err)
	}
	for _, target := range reused.Targets {
		if target.Existing == nil {
			t.Fatal("Group approval not reusable")
		}
	}
}
