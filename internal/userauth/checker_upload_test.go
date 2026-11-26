// SPDX-License-Identifier: Apache-2.0

package userauth

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"testing"
	"time"

	"github.com/jay94ks/mydcd/internal/access"
	"github.com/jay94ks/mydcd/internal/mydcp"
	checker "github.com/jay94ks/mydcd/internal/workload/lifecycle"
)

// Only this test adapter's quorum decision is simulated. The authenticated Unix
// exchange and durable source/retention code are the actual implementations.
func (b *sourceTestBackend) BeginPublication(ctx context.Context, s access.Session, d checker.SourceDescriptor, id [32]byte, recover bool) (func(), error) {
	if err := b.Permit(ctx, s, d, recover); err != nil {
		return nil, err
	}
	if !recover {
		if err := b.store.BeginUpload(ctx, d, id); err != nil {
			return nil, err
		}
	}
	return b.store.HoldUpload(ctx, d, id, recover)
}
func (b *sourceTestBackend) StagePublication(ctx context.Context, s access.Session, d checker.SourceDescriptor, id [32]byte, data []byte) (checker.SourceFact, error) {
	if _, err := b.Stage(ctx, s, d, data); err != nil {
		return checker.SourceFact{}, err
	}
	return b.store.UploadedFact(ctx, d, id, false)
}
func (b *sourceTestBackend) RecoverPublication(ctx context.Context, s access.Session, d checker.SourceDescriptor, id [32]byte) (checker.SourceFact, error) {
	if err := b.Permit(ctx, s, d, true); err != nil {
		return checker.SourceFact{}, err
	}
	return b.store.UploadedFact(ctx, d, id, true)
}
func (b *sourceTestBackend) StagePublicationModule(ctx context.Context, s access.Session, d checker.SourceDescriptor, id [32]byte, a checker.ModuleArchive) (checker.ModuleFact, error) {
	return b.StageModule(ctx, s, d, a)
}
func (b *sourceTestBackend) RecoverPublicationModule(ctx context.Context, s access.Session, d checker.SourceDescriptor, _ [32]byte, pin checker.ModulePin) (checker.ModuleFact, error) {
	return b.RecoverModule(ctx, s, d, pin)
}
func (b *sourceTestBackend) ValidatePublication(context.Context, access.Session, checker.SourceDescriptor, [32]byte, []byte) (*checker.SourceFact, []checker.SourceDiagnostic, error) {
	return nil, nil, checker.ErrSourceStore
}
func TestCheckerOriginalUploadTokenSurvivesLostUnixReplyAndPhysicalGC(t *testing.T) {
	c, peer, session, b := sourceStreamFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	intent := CheckerScriptIntent{Signature: ed25519.Sign(c.Self.Private, []byte("original immutable upload"))}
	c = c.WithCheckerUpload(intent)
	data := []byte("package checker\n")
	d := streamedSource(data)
	b.mu.Lock()
	b.loseReply = true
	b.mu.Unlock()
	if _, err := c.StageCheckerSource(ctx, peer, session, d, data); err == nil {
		t.Fatal("lost write response was successful")
	}
	fact, err := c.RecoverCheckerSource(ctx, peer, session, d)
	if err != nil || fact.Upload == nil || *fact.Upload != *c.checkerUpload {
		t.Fatal("original upload identity lost", err)
	}
	book, err := checker.NewCatalog(c.Cluster)
	if err != nil {
		t.Fatal(err)
	}
	policy := b.policy
	policy.Revision = 0
	book, err = book.SetPolicy(b.users, "operator", 0, policy)
	if err != nil {
		t.Fatal(err)
	}
	book, err = book.PutScript(b.users, "operator", 0, d.Tenant, "check", fact)
	if err != nil {
		t.Fatal(err)
	}
	book, err = book.RetireScript(b.users, "operator", 1, d.Tenant, checker.NamedReference{Name: "check", Revision: 1}, false)
	if err != nil {
		t.Fatal(err)
	}
	book, err = book.RetireScript(b.users, "operator", 2, d.Tenant, checker.NamedReference{Name: "check", Revision: 1}, true)
	if err != nil {
		t.Fatal(err)
	}
	result, err := b.store.CollectCache(ctx, func(context.Context) (checker.CacheRetention, error) {
		return checker.CacheRetention{Catalog: book}, nil
	})
	if err != nil || result.Sources != 1 {
		t.Fatal("actual source bytes not reclaimed after exact publication/delete", result, err)
	}
	if _, err := c.RecoverCheckerSource(ctx, peer, session, d); err == nil {
		t.Fatal("old fact advertised cached bytes")
	}
	if _, err := c.StageCheckerSource(ctx, peer, session, d, data); err == nil {
		t.Fatal("consumed original auto reuploaded")
	} else {
		var response *Error
		if !errors.As(err, &response) || response.Code != "invalid" || response.Phase != mydcp.Completed || ctx.Err() != nil {
			t.Fatal("initial rejection did not close both Unix stream halves", err)
		}
	}
	fresh := c.WithCheckerUpload(CheckerScriptIntent{Signature: ed25519.Sign(c.Self.Private, []byte("explicit different upload"))})
	renewed, err := fresh.StageCheckerSource(ctx, peer, session, d, data)
	if err != nil || renewed.Upload == nil || *renewed.Upload == *fact.Upload || renewed.ContentDigest() != fact.ContentDigest() {
		t.Fatal("new original failed to stage same immutable bytes", err)
	}
	if _, err := b.store.CollectCache(ctx, func(context.Context) (checker.CacheRetention, error) {
		return checker.CacheRetention{Catalog: book}, nil
	}); err != nil {
		t.Fatal(err)
	}
	if got, err := b.store.Read(ctx, d); err != nil || !bytes.Equal(got, data) {
		t.Fatal("old tombstone erased newer unpublished upload", err)
	}
}
func TestCheckerUploadTokenCannotRecoverAnotherIntentOrAllocateOnRead(t *testing.T) {
	c, peer, session, b := sourceStreamFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	first := c.WithCheckerUpload(CheckerScriptIntent{Signature: ed25519.Sign(c.Self.Private, []byte("first"))})
	second := c.WithCheckerUpload(CheckerScriptIntent{Signature: ed25519.Sign(c.Self.Private, []byte("second"))})
	data := []byte("package checker\n")
	d := streamedSource(data)
	if _, err := first.StageCheckerSource(ctx, peer, session, d, data); err != nil {
		t.Fatal(err)
	}
	if _, err := second.RecoverCheckerSource(ctx, peer, session, d); err == nil {
		t.Fatal("lookup fabricated another upload")
	}
	if _, err := b.store.HoldUpload(ctx, d, *second.checkerUpload, true); err == nil {
		t.Fatal("failed lookup created retention hold")
	}
	b.mu.Lock()
	b.denied = true
	b.mu.Unlock()
	if _, err := first.RecoverCheckerSource(ctx, peer, session, d); err == nil {
		t.Fatal("token bypassed current authentication")
	}
	if _, err := first.StageCheckerSource(ctx, peer, session, d, data); err == nil {
		t.Fatal("token granted new write after revoke")
	}
	if _, err := b.store.Read(ctx, d); errors.Is(err, checker.ErrSourceUncertain) {
		t.Fatal("auth failure mutated local store", err)
	}
}
