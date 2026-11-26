// SPDX-License-Identifier: Apache-2.0

package userauth

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/jay94ks/mydcd/internal/access"
	"github.com/jay94ks/mydcd/internal/identity"
	checker "github.com/jay94ks/mydcd/internal/workload/lifecycle"
)

func composeSourceDocument() []byte {
	source := "package checker\n// literal $UNEXPANDED\n" + strings.Repeat("// original source\n", 4000)
	source = "          " + strings.ReplaceAll(source, "\n", "\n          ")
	return []byte("name: source-app\nx-mydc:\n  lifecycle:\n    scripts:\n      inline:\n        source: |\n" + source + "\nservices:\n  web:\n    image: docker.io/library/php@sha256:" + strings.Repeat("a", 64) + "\n    x-mydc:\n      lifecycle:\n        checks:\n          - {id: custom, phase: readiness, script: inline}\n")
}

func stagedComposeSources(t *testing.T) (string, Client, access.Session, *identity.Identity, ComposeSourcePreparation) {
	t.Helper()
	home, c, session, issuer := journalFixture(t)
	p, err := StageComposeSources(home, c, session, "source-operation", "tenant", "", "", "", c.Peers[0], composeSourceDocument())
	if err != nil {
		t.Fatal(err)
	}
	return home, c, session, issuer, p
}

func TestComposeSourcePreparationChunksPrivacyAndOriginalInput(t *testing.T) {
	home, c, session, _, original := stagedComposeSources(t)
	if original.Length <= 64<<10 || len(original.Aliases()) != 1 || original.Aliases()[0] != "inline" {
		t.Fatal("fixture did not exercise bounded document parts")
	}
	if _, err := json.Marshal(original); err == nil || fmt.Sprintf("%+v", original) != "[redacted compose source preparation]" {
		t.Fatal("ordinary output leaked preparation")
	}
	loaded, err := LoadComposeSources(home, c, session, original.ID)
	if err != nil || loaded.Digest() != original.Digest() || !bytes.Equal(loaded.Document, original.Document) {
		t.Fatal("original document readback", err)
	}
	again, err := StageComposeSources(home, c, session, original.ID, "tenant", "", "", "", c.Peers[0], composeSourceDocument())
	if err != nil || again.Digest() != original.Digest() {
		t.Fatal("repeated prepare replaced original signature", err)
	}
	for _, change := range []func(*ComposeSourcePreparation){
		func(p *ComposeSourcePreparation) { p.Document[0] ^= 1 },
		func(p *ComposeSourcePreparation) { p.Provider.Key[0] ^= 1 },
		func(p *ComposeSourcePreparation) { p.Tenant = "other" },
		func(p *ComposeSourcePreparation) { p.Project = "other" },
	} {
		loaded, err := LoadComposeSources(home, c, session, original.ID)
		if err != nil {
			t.Fatal(err)
		}
		change(&loaded)
		if _, err := StageComposeCheckerSource(home, c, session, loaded, "inline"); err == nil {
			t.Fatal("changed parent accepted for child")
		}
	}
	if _, err := StageComposeSources(home, c, session, original.ID, "other", "", "", "", c.Peers[0], original.Document); err == nil {
		t.Fatal("changed tenant reset operation")
	}
}

func TestComposeSourceChildUsesOriginalParentAndNeverNamedRegistration(t *testing.T) {
	home, c, session, issuer, parent := stagedComposeSources(t)
	child, err := StageComposeCheckerSource(home, c, session, parent, "inline")
	if err != nil || !ComposeCheckerSourceMatches(parent, "inline", child) || child.ID != parent.SourceID("inline") {
		t.Fatal("source child binding", err)
	}
	before := child
	child.Sequence++
	if err := ReplaceCheckerScript(home, c, session, before, child); err != nil {
		t.Fatal(err)
	}
	fact := checker.SourceFact{Upload: c.WithCheckerUpload(child).checkerUpload, Schema: 1, Cluster: c.Cluster, Owner: issuer.Public, Tenant: child.Tenant,
		SDK: child.Descriptor.SDK, Digest: child.Descriptor.Digest, Length: child.Descriptor.Length, Modules: child.Descriptor.Modules}
	fact.Signature = ed25519.Sign(issuer.Private, checker.SourceFactBytes(fact))
	before = child
	child.Fact = &fact
	if err := ReplaceCheckerScript(home, c, session, before, child); err != nil {
		t.Fatal(err)
	}
	if _, err := PrepareCheckerRegistration(context.Background(), c, c.Peers[0], session, child); err == nil {
		t.Fatal("compose staging published named script")
	}
	copy := child
	copy.Compose = nil
	if validCheckerIntent(c, session.User, copy) || ReplaceCheckerScript(home, c, session, child, copy) == nil {
		t.Fatal("parent was stripped from original signature")
	}
	if _, err := LoadCompose(home, c, session, parent.ID); !errors.Is(err, ErrOperationMissing) {
		t.Fatal("source cache fact was treated as accepted app", err)
	}
	if _, err := LoadOperation(home, c, session, child.ID); !errors.Is(err, ErrOperationMissing) {
		t.Fatal("source staging created Raft operation", err)
	}
}

func TestComposeSourcesReloginAndMovedEndpointUseCurrentProviderTrust(t *testing.T) {
	home, original, session, issuer, parent := stagedComposeSources(t)
	current := original
	current.Peers = append(current.Peers[:0:0], original.Peers...)
	current.Peers[0].Endpoint = "127.0.0.1:8443"
	self, err := identity.Ephemeral()
	if err != nil {
		t.Fatal(err)
	}
	defer clear(self.Private)
	current.Self = self
	login := session
	login.ID, login.Key = "new-session", self.Public
	login.Signature = ed25519.Sign(issuer.Private, access.SessionBytes(login))
	loaded, err := LoadComposeSources(home, current, login, parent.ID)
	if err != nil || loaded.Digest() != parent.Digest() || loaded.Initiator.Key != session.Key {
		t.Fatal("relogin replaced original", err)
	}
	child, err := StageComposeCheckerSource(home, current, login, loaded, "inline")
	if err != nil || !ComposeCheckerSourceMatches(loaded, "inline", child) || child.Initiator.Key != self.Public || child.Provider.Endpoint != parent.Provider.Endpoint {
		t.Fatal("explicit resume did not preserve parent/current child authentication", err)
	}
	peer, err := CheckerProviderPeer(current, child.Provider)
	if err != nil || peer.Endpoint != current.Peers[0].Endpoint {
		t.Fatal("actual send did not use current approved address", err)
	}
	removed := current
	removed.Peers = append(removed.Peers[:0:0], current.Peers...)
	removed.Peers[0].Key[0] ^= 1
	if _, err := CheckerProviderPeer(removed, child.Provider); err == nil {
		t.Fatal("old parent restored removed provider pin")
	}
}
