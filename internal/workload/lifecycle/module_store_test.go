// SPDX-License-Identifier: Apache-2.0

package lifecycle

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"path/filepath"
	"testing"

	"github.com/jay94ks/mydcd/internal/storage"
)

func TestCheckerModuleActualDBAndRootConsumeOneInspectedCache(t *testing.T) {
	ctx := context.Background()
	file := filepath.Join(t.TempDir(), "observations.db")
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{121}, 32))
	defer clear(key)
	cluster := [32]byte{122}
	db, err := storage.Open(file)
	if err != nil {
		t.Fatal(err)
	}
	store, err := OpenSources(db, cluster, key)
	if err != nil {
		db.Close()
		t.Fatal(err)
	}
	defer func() { store.Close(); db.Close() }()
	archive := moduleArchive(t, "example.invalid/safe", map[string][]byte{"safe.go": []byte("package safe\nconst Ready = true\n")})
	root := scriptSource(`"example.invalid/safe";`, `if !safe.Ready { return lifecycle.Result{}, nil }; `+passBody)
	p, d, target := resolverInput(root, []ModuleArchive{archive}, "example.invalid/safe")
	fact, err := store.StageModule(ctx, d, archive, p)
	if err != nil || fact.Verify() != nil || fact.ExpandedBytes == 0 {
		t.Fatal("actual module persistence", err)
	}
	if _, err = store.Stage(ctx, d, root, p); err != nil {
		t.Fatal(err)
	}
	originalCost := store.bytes[d.Tenant]
	if repeated, err := store.StageModule(ctx, d, archive, p); err != nil || !bytes.Equal(repeated.Signature, fact.Signature) || store.bytes[d.Tenant] != originalCost {
		t.Fatal("module replay changed original fact/budget", err)
	}
	source, err := store.Resolve(ctx, d, p, target)
	if err != nil || len(source.SourceFiles()) != 2 || source.MaterializedBytes() != d.Length+archive.Pin.Length+fact.ExpandedBytes {
		t.Fatal("actual cache did not feed product resolver", err)
	}
	if err = store.Close(); err != nil {
		t.Fatal(err)
	}
	if err = db.Close(); err != nil {
		t.Fatal(err)
	}
	db, err = storage.Open(file)
	if err != nil {
		t.Fatal(err)
	}
	store, err = OpenSources(db, cluster, key)
	if err != nil {
		t.Fatal(err)
	}
	recovered, err := store.RecoverModule(ctx, d.Tenant, archive.Pin)
	if err != nil || !bytes.Equal(recovered.Signature, fact.Signature) || store.bytes[d.Tenant] != originalCost {
		t.Fatal("same DB recovery changed signed module/budget", err)
	}
	read, err := store.ReadModule(ctx, d.Tenant, archive.Pin)
	if err != nil || !bytes.Equal(read, archive.ZIP) {
		t.Fatal("module bytes missing", err)
	}
	read[0] ^= 1
	if _, err := store.Resolve(ctx, d, p, target); err != nil {
		t.Fatal("caller bytes aliased cache", err)
	}
	foreign := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{123}, 32))
	defer clear(foreign)
	if other, err := OpenSources(db, cluster, foreign); err == nil {
		other.Close()
		t.Fatal("foreign owner adopted module data")
	}
}

func TestCheckerModuleAndRootShareTenantQuotaWithoutCrossTenantAlias(t *testing.T) {
	db, err := storage.Open(filepath.Join(t.TempDir(), "observations.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	store, err := OpenSources(db, [32]byte{124}, ed25519.NewKeyFromSeed(bytes.Repeat([]byte{125}, 32)))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	root := []byte("package checker\n")
	archive := moduleArchive(t, "example.invalid/safe", map[string][]byte{"safe.go": []byte("package safe\n"), "LICENSE": bytes.Repeat([]byte("x"), 120<<10)})
	p, d, _ := resolverInput(root, []ModuleArchive{archive}, "example.invalid/safe")
	p.Resolver.SourceCacheBytes = MaxScriptBytes
	if _, err := store.StageModule(context.Background(), d, archive, p); err != nil {
		t.Fatal(err)
	}
	otherRoot := bytes.Repeat([]byte("a"), 32<<10)
	other := sourceDescriptor(d.Tenant, otherRoot)
	if _, err := store.Stage(context.Background(), other, otherRoot, p); err == nil {
		t.Fatal("root ignored module ZIP/expanded/metadata reservation")
	}
	p.Tenant, d.Tenant = "other", "other"
	fact, err := store.StageModule(context.Background(), d, archive, p)
	if err != nil || fact.Tenant != "other" || len(store.modules) != 2 {
		t.Fatal("tenant cache namespace shared", err)
	}
	p.Enabled = false
	if _, err := store.StageModule(context.Background(), d, archive, p); err == nil {
		t.Fatal("disabled policy admitted staging")
	}
	if _, err := store.RecoverModule(context.Background(), d.Tenant, archive.Pin); err != nil {
		t.Fatal("revocation destroyed original cleanup", err)
	}
}

func TestCheckerModuleCorruptionAndOrphanDataCannotBecomePositiveMissingOrRepair(t *testing.T) {
	for _, variant := range []string{"module-data", "module-metadata", "root-metadata"} {
		t.Run(variant, func(t *testing.T) {
			db, err := storage.Open(filepath.Join(t.TempDir(), "observations.db"))
			if err != nil {
				t.Fatal(err)
			}
			defer db.Close()
			store, err := OpenSources(db, [32]byte{126}, ed25519.NewKeyFromSeed(bytes.Repeat([]byte{127}, 32)))
			if err != nil {
				t.Fatal(err)
			}
			defer store.Close()
			archive := moduleArchive(t, "example.invalid/safe", map[string][]byte{"safe.go": []byte("package safe\n")})
			root := scriptSource("", passBody)
			p, d, _ := resolverInput(root, []ModuleArchive{archive})
			if _, err := store.StageModule(context.Background(), d, archive, p); err != nil {
				t.Fatal(err)
			}
			if _, err := store.Stage(context.Background(), d, root, p); err != nil {
				t.Fatal(err)
			}
			key := moduleDataPrefix + moduleObjectKey(d.Tenant, archive.Pin)
			var broken []byte
			if variant == "module-data" {
				broken = []byte("corrupt")
			}
			if variant == "module-metadata" {
				key = moduleMetaPrefix + moduleObjectKey(d.Tenant, archive.Pin)
			}
			if variant == "root-metadata" {
				key = sourceMetaPrefix + sourceObjectKey(d)
			}
			if err := db.Write(map[string][]byte{key: broken}); err != nil {
				t.Fatal(err)
			}
			if variant == "root-metadata" {
				if _, err := store.Recover(context.Background(), d); !errors.Is(err, ErrSourceStore) {
					t.Fatal("orphan root became missing", err)
				}
				if _, err := store.Stage(context.Background(), d, root, p); err == nil {
					t.Fatal("orphan root automatically overwritten")
				}
			} else {
				if _, err := store.RecoverModule(context.Background(), d.Tenant, archive.Pin); !errors.Is(err, ErrSourceStore) {
					t.Fatal("broken module became missing", err)
				}
				if _, err := store.StageModule(context.Background(), d, archive, p); err == nil {
					t.Fatal("original module overwritten")
				}
			}
		})
	}
}
