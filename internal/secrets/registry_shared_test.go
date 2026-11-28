// SPDX-License-Identifier: Apache-2.0

package secrets

import (
	"testing"

	"github.com/jay94ks/seafield/internal/access"
)

// sharedFixture is a cluster tree with a Group "registry" holding registry
// credentials, and the group's RegistryShared flag set as asked.
func sharedFixture(t *testing.T, shared bool) (fixture, Tree) {
	t.Helper()
	f := makeFixture(t)
	global, err := NewTree(f.t.cluster, "", "root")
	global = mustTree(t, global, err)
	if _, err = global.Create(f.c, "admin", global.Revision(), Object{ID: "early", Parent: "root", Kind: Group, ACL: ACL{RegistryShared: true}}); err == nil {
		t.Fatal("a group was created already shared")
	}
	for _, o := range []Object{
		{ID: "registry", Parent: "root", Kind: Group},
		{ID: "hub-cred", Parent: "registry", Kind: Secret, Reference: Reference{Profile: "vault", Object: "system/hub", Revision: 1, Keys: []string{"USERNAME", "PASSWORD"}}},
		{ID: "plain", Parent: "root", Kind: Secret, Reference: Reference{Profile: "vault", Object: "system/plain", Revision: 1, Keys: []string{"KEY"}}},
	} {
		global, err = global.Create(f.c, "admin", global.Revision(), o)
		global = mustTree(t, global, err)
	}
	if shared {
		o, _ := global.Object("registry")
		global, err = global.SetRegistryShared(f.c, "admin", "registry", o.Revision, true)
		global = mustTree(t, global, err)
	}
	return f, global
}

func registryPull(f fixture, tenant string, sources ...string) Use {
	u := web(f)
	u.Tenant = tenant
	u.Sources = sources
	u.RegistrySources = sources
	return u
}

func clusterConsumer(f fixture, user string, sources ...string) Use {
	u := web(f)
	u.Tenant = ""
	u.User = user
	u.Purpose = PurposeRegistrySource
	u.Sources = sources
	u.RegistrySources = sources
	return u
}

func TestRegistrySharedNeedsSystemAdminOnAClusterGroup(t *testing.T) {
	f, global := sharedFixture(t, false)
	o, _ := global.Object("registry")
	if _, err := global.SetRegistryShared(f.c, "alice", "registry", o.Revision, true); err != access.ErrDenied {
		t.Fatal("a workspace manager shared a cluster group", err)
	}
	if _, err := global.SetRegistryShared(f.c, "admin", "registry", o.Revision-1, true); err != access.ErrConflict {
		t.Fatal("stale revision accepted", err)
	}
	if _, err := global.SetRegistryShared(f.c, "admin", "registry", o.Revision, false); err != ErrPolicy {
		t.Fatal("no-op change accepted", err)
	}
	s, _ := global.Object("hub-cred")
	if _, err := global.SetRegistryShared(f.c, "admin", "hub-cred", s.Revision, true); err != ErrPolicy {
		t.Fatal("a secret was shared", err)
	}
	g, _ := f.t.Object("app")
	if _, err := f.t.SetRegistryShared(f.c, "admin", "app", g.Revision, true); err != ErrPolicy {
		t.Fatal("a workspace group was shared", err)
	}
	// The ACL edits cannot carry the flag either way.
	if _, err := global.ChangeACL(f.c, "admin", "registry", o.Revision, ACL{RegistryShared: true}, ACL{}); err == nil {
		t.Fatal("ChangeACL set the flag")
	}
	if _, err := global.SetACL(f.c, "admin", "registry", o.Revision, ACL{RegistryShared: true}); err == nil {
		t.Fatal("SetACL set the flag")
	}
}

func TestRegistrySharedOpensImagePullsToEveryWorkspaceButNeverAppInputs(t *testing.T) {
	f, global := sharedFixture(t, false)
	// Not shared yet and no tenant grant: no workspace may read it.
	if _, err := global.Plan(f.c, []Use{registryPull(f, "tenant", "hub-cred")}); err != access.ErrDenied {
		t.Fatal("unshared cluster secret served a pull", err)
	}
	o, _ := global.Object("registry")
	global, err := global.SetRegistryShared(f.c, "admin", "registry", o.Revision, true)
	global = mustTree(t, global, err)
	if _, err = global.Plan(f.c, []Use{registryPull(f, "tenant", "hub-cred")}); err != nil {
		t.Fatal("shared group did not serve the workspace pull", err)
	}
	if _, err = global.Plan(f.c, []Use{registryPull(f, "tenant", "registry")}); err != nil {
		t.Fatal("shared group as a source did not serve the pull", err)
	}
	// An app in another workspace selecting the shared secret as env is refused.
	env := web(f)
	env.Sources = []string{"hub-cred"}
	if _, err = global.Plan(f.c, []Use{env}); err != access.ErrDenied {
		t.Fatal("shared secret selected as an app input", err)
	}
	// Even with an explicit tenant grant, and through an enclosing group.
	root, _ := global.Object("root")
	global, err = global.SetACL(f.c, "admin", "root", root.Revision, ACL{TenantGrants: []string{"tenant"}})
	global = mustTree(t, global, err)
	if _, err = global.Plan(f.c, []Use{env}); err != access.ErrDenied {
		t.Fatal("tenant grant opened the shared secret to app inputs", err)
	}
	env.Sources = []string{"root"}
	if _, err = global.Plan(f.c, []Use{env}); err != access.ErrDenied {
		t.Fatal("enclosing group reached the shared secret as an app input", err)
	}
	env.Sources = []string{"plain"}
	if _, err = global.Plan(f.c, []Use{env}); err != nil {
		t.Fatal("granted plain secret refused", err)
	}
	// Registry sources must be among the use's sources.
	bad := registryPull(f, "tenant", "hub-cred")
	bad.RegistrySources = []string{"plain"}
	if _, err = global.Plan(f.c, []Use{bad}); err != ErrPolicy {
		t.Fatal("registry source outside the sources accepted", err)
	}
	// A pull still needs Deploy on the node in its own workspace.
	stranger := registryPull(f, "other", "hub-cred")
	if _, err = global.Plan(f.c, []Use{stranger}); err != access.ErrDenied {
		t.Fatal("alice pulled for a workspace she cannot deploy to", err)
	}
	stranger.User = "admin"
	if _, err = global.Plan(f.c, []Use{stranger}); err != nil {
		t.Fatal("shared group did not serve another workspace", err)
	}
	// Turning it off closes the pulls again (tenant grant aside).
	o, _ = global.Object("registry")
	global, err = global.SetRegistryShared(f.c, "admin", "registry", o.Revision, false)
	global = mustTree(t, global, err)
	if _, err = global.Plan(f.c, []Use{stranger}); err != access.ErrDenied {
		t.Fatal("unshared group still served another workspace", err)
	}
}

func TestClusterConsumerReadsOnlySharedSecretsAsSystemAdmin(t *testing.T) {
	f, global := sharedFixture(t, true)
	if _, err := global.Plan(f.c, []Use{clusterConsumer(f, "admin", "hub-cred")}); err != nil {
		t.Fatal("cluster source reader refused", err)
	}
	if _, err := global.Plan(f.c, []Use{clusterConsumer(f, "alice", "hub-cred")}); err != access.ErrDenied {
		t.Fatal("non-admin bound a cluster source reader", err)
	}
	if _, err := global.Plan(f.c, []Use{clusterConsumer(f, "admin", "plain")}); err != access.ErrDenied {
		t.Fatal("cluster consumer read an unshared secret", err)
	}
	// The cluster consumer exists only in the cluster realm.
	if _, err := f.t.Plan(f.c, []Use{clusterConsumer(f, "admin", "runtime")}); err != access.ErrDenied {
		t.Fatal("cluster consumer read a workspace tree", err)
	}
	// Without the registry-source purpose an empty tenant is no consumer.
	u := clusterConsumer(f, "admin", "hub-cred")
	u.Purpose = ""
	if _, err := global.Plan(f.c, []Use{u}); err != access.ErrDenied {
		t.Fatal("tenantless app use accepted", err)
	}
	// Losing system administration stops new reads.
	c, err := f.c.PutUser("admin", 0, account("bob", true))
	if err != nil {
		t.Fatal(err)
	}
	if _, err = global.Plan(c, []Use{clusterConsumer(f, "bob", "hub-cred")}); err != nil {
		t.Fatal("system administrator bob refused", err)
	}
	bob, _ := c.User("bob")
	if c, err = c.PutUser("admin", bob.Revision, access.User{ID: "bob", Username: "bob", Enabled: true}); err != nil {
		t.Fatal(err)
	}
	if _, err = global.Plan(c, []Use{clusterConsumer(f, "bob", "hub-cred")}); err != access.ErrDenied {
		t.Fatal("former system administrator still read", err)
	}
}
