// SPDX-License-Identifier: Apache-2.0

package imagebuild

import (
	"context"
	"io"
	"testing"

	bolt "go.etcd.io/bbolt"
)

func TestInputRootOwnershipUsesOriginalDraftAnchorAndPreparedArchiveScope(t *testing.T) {
	store, spool, plan := frozenDraftFixture(t)
	owners, err := StoredInputRootOwners(spool.db, store.scope.Root)
	if err != nil || owners[DraftRootConsumer(store.scope)].Tenant != store.scope.Tenant || !owners[DraftRootConsumer(store.scope)].Required {
		t.Fatal("original draft consumer not classified", owners, err)
	}
	archive, err := store.PrepareFreeze(context.Background(), plan)
	if err != nil {
		t.Fatal(err)
	}
	owners, err = StoredInputRootOwners(spool.db, store.scope.Root)
	if err != nil || owners[ArtifactRootConsumer(archive)].Tenant != archive.Tenant || owners[ArtifactRootConsumer(archive)].Required {
		t.Fatal("pre-adoption archive consumer omitted", owners, err)
	}
	updated := store.scope
	updated.PolicyRevision++
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := OpenDraftStore(spool, updated, false)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	owners, err = StoredInputRootOwners(spool.db, updated.Root)
	if err != nil || owners[DraftRootConsumer(store.scope)].Tenant != store.scope.Tenant || owners[DraftRootConsumer(updated)].Tenant != "" {
		t.Fatal("current configuration replaced original consumer", owners, err)
	}
	if err := spool.db.Update(func(tx *bolt.Tx) error { return store.bucket(tx).Delete([]byte("identity")) }); err != nil {
		t.Fatal(err)
	}
	if _, err := StoredInputRootOwners(spool.db, updated.Root); err == nil {
		t.Fatal("missing original namespace identity ignored")
	}
}

func TestInputRootOwnershipClassifiesGitStagingAndArchiveBeforeAdoption(t *testing.T) {
	spool, repo, plan := gitSaveFixture(t)
	scope, err := spool.PrepareGit(context.Background(), plan, func(out io.Writer) (Tree, error) {
		return WriteGitZIP(context.Background(), repo, plan.Commit, ".", plan.Dockerfile, out, plan.ExpandedLimit)
	})
	if err != nil {
		t.Fatal(err)
	}
	owners, err := StoredInputRootOwners(spool.db, plan.Root)
	if err != nil || owners[GitRootConsumer(plan)].Tenant != plan.Tenant || !owners[GitRootConsumer(plan)].Required || owners[ArtifactRootConsumer(scope)].Tenant != plan.Tenant || owners[ArtifactRootConsumer(scope)].Required {
		t.Fatal("original Git/source archive consumers omitted", owners, err)
	}
}
