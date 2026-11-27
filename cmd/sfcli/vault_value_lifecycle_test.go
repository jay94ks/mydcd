// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/jay94ks/seafield/internal/access"
	"github.com/jay94ks/seafield/internal/identity"
	"github.com/jay94ks/seafield/internal/reconcile"
	"github.com/jay94ks/seafield/internal/secrets"
)

// This is the real fixed-version provider adapter, not a Raft or native test.
// The same public Tree/write core constructs the provider's original intent.
func TestRealVaultPinnedValueDeletionAndReaderExpiry(t *testing.T) {
	v := newOwnedVault(t)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	key, err := identity.Ephemeral()
	if err != nil {
		t.Fatal(err)
	}
	defer clear(key.Private)
	catalog, err := access.New(key.Public)
	if err != nil {
		t.Fatal(err)
	}
	catalog, err = catalog.Enroll(key.Public, access.User{ID: "admin", Username: "admin", Enabled: true, SystemAdmin: true, Credentials: []access.Credential{{ID: "key", Method: access.PrivateKey, PublicKey: key.Public, Enabled: true}}})
	if err != nil {
		t.Fatal(err)
	}
	catalog, err = catalog.CreateTenant("admin", "tenant", 0)
	if err != nil {
		t.Fatal(err)
	}
	clusterID := [32]byte{113}
	tree, err := secrets.NewTree(clusterID, "tenant", "root")
	if err != nil {
		t.Fatal(err)
	}
	tree, err = tree.Create(catalog, "admin", tree.Revision(), secrets.Object{ID: "runtime", Parent: "root", Kind: secrets.Secret, Reference: secrets.Reference{Profile: "values", Object: "tenant/runtime", Keys: []string{"key"}}})
	if err != nil {
		t.Fatal(err)
	}
	tree, err = tree.SetWriteProfile(catalog, "admin", tree.Revision(), secrets.WriteProfile{ID: "values", Node: "node-a", Key: key.Public, Enabled: true, Values: true})
	if err != nil {
		t.Fatal(err)
	}
	v.api("PUT", "sys/policies/acl/sfc-fixed-values", map[string]any{"policy": `path "kv/data/tenant/*" { capabilities = ["create","update","read"] }`}, nil, v.admin)
	var writerToken struct {
		Auth struct {
			Token string `json:"client_token"`
		} `json:"auth"`
	}
	v.api("POST", "auth/token/create", map[string]any{"policies": []string{"sfc-fixed-values"}, "no_default_policy": true, "ttl": "5m"}, &writerToken, v.admin)
	root := t.TempDir()
	open := func(token, name string) *secrets.Vault {
		t.Helper()
		file := filepath.Join(root, name)
		if err := os.WriteFile(file, []byte(token), 0600); err != nil {
			t.Fatal(err)
		}
		profile, err := secrets.InstalledProfile("values", v.address, "kv", "tenant", "", filepath.Join(v.root, "tls.pem"), file)
		if err != nil {
			t.Fatal(err)
		}
		p, err := secrets.NewVault(profile)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(p.Close)
		return p
	}
	provider := open(writerToken.Auth.Token, "writer-token")
	put := func(id, value string) secrets.Reference {
		t.Helper()
		request, err := tree.PlanWrite(catalog, "admin", id, "runtime", "values", secrets.ValueWrite, []string{"key"})
		if err != nil {
			t.Fatal("public original write plan", err)
		}
		tree, err = tree.PrepareWrite(catalog, "admin", tree.Revision(), request)
		if err != nil {
			t.Fatal(err)
		}
		tree, err = tree.DispatchWrite(catalog, "admin", id, request.Epoch, tree.Revision())
		if err != nil {
			t.Fatal(err)
		}
		record, _ := tree.Write(id)
		receipt, err := provider.PutOnce(ctx, record, map[string][]byte{"key": []byte(value)})
		if err != nil {
			t.Fatal(err)
		}
		fact := secrets.WriteObservation{Cluster: clusterID, Tenant: "tenant", Request: record.Request, Generation: record.Generation, ExpectedObjectRevision: record.ExpectedObjectRevision, Writer: record.Writer, Operation: record.Journal.LastID, Outcome: reconcile.EffectApplied, ProviderRevision: receipt.Revision}
		fact.Signature = ed25519.Sign(key.Private, secrets.WriteObservationBytes(fact))
		tree, err = tree.ObserveWrite(fact)
		if err != nil {
			t.Fatal(err)
		}
		tree, err = tree.PublishStored(catalog, "admin", id, request.Epoch, record.ExpectedObjectRevision, tree.Revision())
		if err != nil {
			t.Fatal(err)
		}
		object, _ := tree.Object("runtime")
		return object.Reference
	}
	fixed := put("original", "private-fixed-original")
	latest := put("successor", "private-later-value")
	if fixed.Revision != 1 || latest.Revision != 2 {
		t.Fatal("actual provider revisions")
	}
	check := func(p *secrets.Vault, ref secrets.Reference, want string, allowed bool) {
		t.Helper()
		fetched, err := p.Fetch(ctx, "runtime", ref)
		defer func() {
			for _, v := range fetched.Values {
				clear(v)
			}
		}()
		if allowed {
			if err != nil || !bytes.Equal(fetched.Values["key"], []byte(want)) || fetched.Reference.Revision != ref.Revision {
				t.Fatal("fixed actual provider value", err)
			}
		} else if err == nil || len(fetched.Values) != 0 {
			t.Fatal("unavailable provider record fell back to another value")
		}
	}
	check(provider, fixed, "private-fixed-original", true)
	v.api("POST", "kv/delete/tenant/runtime", map[string]any{"versions": []int{1}}, nil, v.admin)
	check(provider, fixed, "", false)
	check(provider, latest, "private-later-value", true)
	v.api("POST", "kv/undelete/tenant/runtime", map[string]any{"versions": []int{1}}, nil, v.admin)
	check(provider, fixed, "private-fixed-original", true)
	v.api("PUT", "sys/policies/acl/sfc-fixed-reader", map[string]any{"policy": `path "kv/data/tenant/*" { capabilities = ["read"] }`}, nil, v.admin)
	var issued struct {
		Auth struct {
			Token string `json:"client_token"`
			Lease int64  `json:"lease_duration"`
		} `json:"auth"`
	}
	v.api("POST", "auth/token/create", map[string]any{"policies": []string{"sfc-fixed-reader"}, "no_default_policy": true, "ttl": "2s", "explicit_max_ttl": "2s"}, &issued, v.admin)
	if issued.Auth.Lease != 2 {
		t.Fatal("explicit actual reader TTL", issued.Auth.Lease)
	}
	reader := open(issued.Auth.Token, "expiring-reader-token")
	check(reader, fixed, "private-fixed-original", true)
	// This wait exercises real Vault expiry using its returned TTL. No product
	// clock/deadline/budget is altered and no write is retried.
	select {
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	case <-time.After(time.Duration(issued.Auth.Lease+1) * time.Second):
	}
	check(reader, fixed, "", false)
	check(provider, fixed, "private-fixed-original", true)
	t.Log("actual pinned Vault KV2 version1 remains original after version2; deleting version1 refuses without latest/local fallback; explicit undelete restores same version; installed read-only provider credential reads once then real returned TTL expires and Fetch fails while independent authorized reader still succeeds; no raw values/token in shared Tree")
}
