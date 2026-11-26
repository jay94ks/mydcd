// SPDX-License-Identifier: Apache-2.0

//go:build linux

package app

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"os"
	"reflect"
	"testing"
	"time"

	"github.com/jay94ks/mydcd/internal/access"
	"github.com/jay94ks/mydcd/internal/cluster"
	"github.com/jay94ks/mydcd/internal/cluster/control"
	"github.com/jay94ks/mydcd/internal/mydcp"
	"github.com/jay94ks/mydcd/internal/registryclient"
	"github.com/jay94ks/mydcd/internal/userauth"
)

// Reuses the installed registry/retained Volume, CLI wallet, authenticated
// control handoff and owned rollback. This remaining scope does not build an
// image or repeat the app or large-context lifecycle.
func TestRQ6RegistryPruneInstalledFollowerOwnerOriginalResults(t *testing.T) {
	if os.Getenv("MYDC_TEST_RQ6_REMAINING") != "prune-follower" {
		t.Skip("explicit prune-follower remaining scope required")
	}
	if os.Getenv("MYDC_TEST_RQ6_IMAGE_BUILD") == "1" {
		t.Fatal("prune-follower uses the installed registry fixture without the image-build opt-in")
	}
	if os.Getenv("MYDC_REGISTRY_TEST_IP") == "" || os.Getenv("MYDC_STORAGE_TEST_ROOT") == "" || os.Getenv("MYDC_STORAGE_TEST_OWNER") == "" || os.Getenv("MYDC_STORAGE_HOST_MOUNT_NS") == "" {
		t.Skip("installed registry IPv4 and owned storage/mount rollback inputs required")
	}
	runManagedAppOwner(t, true, true, true, true, managedAppRegistry, true, false, false)
}

func (f *managedRegistryNative) verifyRegistryPruneFollowerNative(t *testing.T, ctx context.Context, owner, remote *Runtime, user userauth.Client, peer mydcp.Peer, p control.Policy, read func() cluster.View, change func(string, string, uint64, any)) {
	t.Helper()
	if owner == nil || remote == nil || f.spec.Node != "node-a" || f.original.Owner != owner.Identity.Public || !owner.Engine().IsLeader() {
		t.Fatal("prune follower requires the original installed node-a registry owner")
	}
	remotePeer, found := owner.Mesh.Peer(mydcp.Identity(remote.Identity.Public))
	if !found || remotePeer.ID != "node-c" || !remotePeer.Member {
		t.Fatal("prune follower requires the installed node-c control")
	}
	waitLeader := func(r *Runtime) error {
		for !r.Engine().IsLeader() {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(20 * time.Millisecond):
			}
		}
		_, err := r.Engine().Read(ctx, true)
		return err
	}
	if err := owner.Engine().TransferLeadership(ctx, remotePeer.ID, remotePeer.Endpoint); err != nil {
		t.Fatal("prune follower leadership transfer", err)
	}
	defer func() {
		if err := remote.Engine().TransferLeadership(ctx, peer.ID, peer.Endpoint); err != nil {
			t.Error("restore prune fixture leadership", err)
			return
		}
		if err := waitLeader(owner); err != nil {
			t.Error("restored prune fixture barrier", err)
		}
	}()
	if err := waitLeader(remote); err != nil || owner.Engine().IsLeader() {
		t.Fatal("prune owner did not remain a follower", err)
	}

	checkOriginal := func() {
		t.Helper()
		view := read()
		registries, err := p.Registries(view.State)
		if err != nil {
			t.Fatal(err)
		}
		entry, found := registries.Entry("tenant", "private")
		if !found || entry.Active == nil || entry.Active.Owner != owner.Identity.Public || entry.Spec.Node != "node-a" || !reflect.DeepEqual(entry.Active.Reference(), f.original) {
			t.Fatal("leadership handoff changed the original registry run/owner")
		}
		volumes, err := p.Volumes(view.State)
		if err != nil {
			t.Fatal(err)
		}
		creation, found := volumes.Creation(f.spec.Volume)
		if !found || creation.Ready == nil || !reflect.DeepEqual(*creation.Ready, f.native) {
			t.Fatal("leadership handoff changed the original native Volume")
		}
		if owner.Engine().IsLeader() || !remote.Engine().IsLeader() {
			t.Fatal("prune no longer exercises its installed follower owner")
		}
	}
	checkOriginal()
	const id = "rq6-registry-follower-empty-prune"
	// This performs a fresh owner-signed preview, the same typed CLI/User/Raft
	// prune action, original ID replay and prune-items through node-a's relay.
	original := f.verifyEmptyRegistryPruneOperation(t, ctx, p, read, id)
	run := f.original
	run.Ready = nil
	if original.Change.OwnerKey() != owner.Identity.Public || original.Change.Operation != id || original.Change.Prune == nil || !original.Change.Prune.Valid(p.Cluster, original.Change) || !reflect.DeepEqual(original.Change.Run, run) {
		t.Fatal("follower prune changed its signed fact or original target")
	}
	checkOriginal()

	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(key)
	const username = "prune-follower-reader"
	change("prune-follower-reader-put", "put-user", 0, access.User{ID: username, Username: username, Enabled: true, Credentials: []access.Credential{{ID: "key", Method: access.PrivateKey, PublicKey: [32]byte(pub), Enabled: true}}})
	change("prune-follower-reader-member", "set-membership", 0, access.Membership{Tenant: "tenant", User: username, Role: access.Manager, Enabled: true})
	change("prune-follower-other-tenant", "create-tenant", 0, control.TenantID{ID: "prune-other"})
	change("prune-follower-reader-other-member", "set-membership", 0, access.Membership{Tenant: "prune-other", User: username, Role: access.Manager, Enabled: true})
	session, err := user.Login(ctx, peer, username, key)
	if err != nil {
		t.Fatal("prune follower current reader login", err)
	}
	conditions := registryclient.PruneConditions{}
	previewQuery := control.RegistryPruneQuery{ID: "private", Part: "items", Conditions: &conditions}
	resultQuery := control.RegistryPruneQuery{Operation: id, Part: "items"}
	if _, err := user.RegistryPrune(ctx, peer, session, "tenant", previewQuery, "", false); err != nil {
		t.Fatal("current member follower preview", err)
	}
	if _, err := user.RegistryPrune(ctx, peer, session, "tenant", resultQuery, "", true); err != nil {
		t.Fatal("current member original follower results", err)
	}
	if _, err := user.Query(ctx, peer, session, "select-tenant", "prune-other"); err != nil {
		t.Fatal("foreign tenant reader lacks its own valid membership", err)
	}
	deny := func(tenant string, query control.RegistryPruneQuery, results bool) {
		t.Helper()
		out, err := user.RegistryPrune(ctx, peer, session, tenant, query, "", results)
		var rejected *userauth.Error
		if !errors.As(err, &rejected) || rejected.Code != "denied" || out.Schema != 0 {
			t.Fatal("follower prune exposed another tenant or revoked reader's native metadata", tenant, results, err)
		}
	}
	deny("prune-other", previewQuery, false)
	deny("prune-other", resultQuery, true)

	accepted, err := p.RegistryPruneRead(read().State, session, time.Now().Unix(), "tenant", resultQuery, "", true)
	if err != nil {
		t.Fatal("original accepted reader result scope", err)
	}
	// Call the real owner result adapter as well: it reads the original local
	// maintenance receipt/items before its final current-prefix permission gate.
	// Keep that same accepted read when membership is revoked below, so success
	// cannot be supplied by a newly authorized read or a stale local prefix.
	if out, err := owner.registryPruneResultsOwner(ctx, accepted); err != nil || !out.Valid(accepted, true) {
		t.Fatal("original owner result adapter success control", err)
	}
	catalog, err := p.Catalog(read().State)
	if err != nil {
		t.Fatal(err)
	}
	member, found := catalog.Membership("tenant", username)
	if !found {
		t.Fatal("original reader membership missing")
	}
	change("prune-follower-reader-revoke", "set-membership", member.Revision, access.Membership{Tenant: "tenant", User: username, Role: access.Manager, Enabled: false})
	if out, err := owner.registryPruneResultsOwner(ctx, accepted); !errors.Is(err, mydcp.ErrAdmission) || out.Schema != 0 {
		t.Fatal("post-I/O follower result gate reused revoked membership", err)
	}
	deny("tenant", previewQuery, false)
	deny("tenant", resultQuery, true)
	checkOriginal()
	f.public["RegistryRQ6PruneFollowerOwner"], f.public["RegistryRQ6PruneFollowerLeader"] = "node-a", "node-c"
	f.public["RegistryRQ6PruneFollowerOriginalOperation"], f.public["RegistryRQ6PruneFollowerCurrentMembershipAndTenant"] = id, true
	f.save()
}
