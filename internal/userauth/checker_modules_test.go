// SPDX-License-Identifier: Apache-2.0

package userauth

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"testing"
	"time"

	"github.com/jay94ks/mydcd/internal/access"
	"github.com/jay94ks/mydcd/internal/mydcp"
	"github.com/jay94ks/mydcd/internal/storage"
	checker "github.com/jay94ks/mydcd/internal/workload/lifecycle"
)

func (b *sourceTestBackend) StageModule(ctx context.Context, s access.Session, d checker.SourceDescriptor, a checker.ModuleArchive) (checker.ModuleFact, error) {
	if err := b.Permit(ctx, s, d, false); err != nil {
		return checker.ModuleFact{}, err
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	b.stages++
	fact, err := b.store.StageModule(ctx, d, a, b.policy)
	if err == nil && b.loseReply {
		b.loseReply = false
		return checker.ModuleFact{}, checker.ErrSourceUncertain
	}
	return fact, err
}
func (b *sourceTestBackend) RecoverModule(ctx context.Context, s access.Session, d checker.SourceDescriptor, pin checker.ModulePin) (checker.ModuleFact, error) {
	if err := b.Permit(ctx, s, d, true); err != nil {
		return checker.ModuleFact{}, err
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.store.RecoverModule(ctx, d.Tenant, pin)
}

func streamModule(t *testing.T) checker.ModuleArchive {
	t.Helper()
	var data bytes.Buffer
	w := zip.NewWriter(&data)
	file, err := w.CreateHeader(&zip.FileHeader{Name: "example.invalid/safe@v1.0.0/safe.go", Method: zip.Store})
	if err != nil {
		t.Fatal(err)
	}
	_, err = file.Write(append([]byte("package safe\n"), bytes.Repeat([]byte("// safe source\n"), 8000)...))
	if err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return checker.ModuleArchive{Pin: checker.ModulePin{Path: "example.invalid/safe", Version: "v1.0.0", Digest: sha256.Sum256(data.Bytes()), Length: uint64(data.Len())}, ZIP: data.Bytes()}
}

func TestCheckerModuleActualUnixChunksLostFactAndCurrentRevocation(t *testing.T) {
	c, peer, session, backend := sourceStreamFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	a := streamModule(t)
	root := []byte("package checker\n")
	d := streamedSource(root)
	d.Modules = []checker.ModulePin{a.Pin}
	backend.mu.Lock()
	backend.policy.Resolver.Modules = []checker.ModulePin{a.Pin}
	backend.loseReply = true
	backend.mu.Unlock()
	if _, err := c.StageCheckerModule(ctx, peer, session, d, a); err == nil {
		t.Fatal("lost fact manufactured success")
	} else {
		var outcome *Error
		if !errors.As(err, &outcome) || outcome.Phase == mydcp.Completed {
			t.Fatal("module uncertainty lost", err)
		}
	}
	fact, err := c.RecoverCheckerModule(ctx, peer, session, d, a.Pin)
	if err != nil || fact.Verify() != nil || fact.Module != a.Pin {
		t.Fatal("same authenticated module recovered", err)
	}
	read, err := backend.store.ReadModule(ctx, d.Tenant, a.Pin)
	if err != nil || !bytes.Equal(read, a.ZIP) {
		t.Fatal("bounded ZIP transfer changed actual data", err)
	}
	backend.mu.Lock()
	stages := backend.stages
	backend.policy.Enabled = false
	backend.mu.Unlock()
	if stages != 1 {
		t.Fatal("implicit upload repeated")
	}
	again, err := c.RecoverCheckerModule(ctx, peer, session, d, a.Pin)
	if err != nil || !bytes.Equal(again.Signature, fact.Signature) {
		t.Fatal("policy revocation erased original fact", err)
	}
	if _, err := c.StageCheckerModule(ctx, peer, session, d, a); err == nil {
		t.Fatal("new upload bypassed current policy")
	}
	backend.mu.Lock()
	stages = backend.stages
	backend.mu.Unlock()
	if stages != 1 {
		t.Fatal("denied upload reached cache")
	}
}

func TestCheckerModuleRechecksPermitAfterReceiveAndNeverStagesUnlistedPin(t *testing.T) {
	c, peer, session, backend := sourceStreamFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	a := streamModule(t)
	d := streamedSource([]byte("package checker\n"))
	d.Modules = []checker.ModulePin{a.Pin}
	if _, err := c.StageCheckerModule(ctx, peer, session, streamedSource([]byte("package checker\n")), a); err == nil {
		t.Fatal("unlisted module reached remote upload")
	}
	backend.mu.Lock()
	backend.policy.Resolver.Modules = []checker.ModulePin{a.Pin}
	backend.denyAfterPermit = true
	backend.mu.Unlock()
	if _, err := c.StageCheckerModule(ctx, peer, session, d, a); err == nil {
		t.Fatal("permission revoked during input still staged")
	}
	if _, err := backend.store.RecoverModule(ctx, d.Tenant, a.Pin); !errors.Is(err, storage.ErrMissing) {
		t.Fatal("denied upload published data", err)
	}
	backend.mu.Lock()
	defer backend.mu.Unlock()
	if backend.stages != 0 {
		t.Fatal("revoked upload invoked stage")
	}
}
