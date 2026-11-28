// SPDX-License-Identifier: Apache-2.0

package userauth

import (
	"crypto/sha256"
	"testing"

	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/deployment"
)

func TestCDReadSelectorsCannotBorrowMutationOrAnotherMethod(t *testing.T) {
	for _, method := range []string{"app-cd-history", "app-cd-diff"} {
		base := Request{Schema: 1, Method: method, Tenant: "tenant", AppCDRead: &control.AppCDReadRequest{App: "app"}}
		if !base.validMethodFields() || !base.validQuerySelectors() {
			t.Fatal("valid CD read rejected", method)
		}
		for _, alter := range []func(*Request){func(r *Request) { r.Node = "node-a" }, func(r *Request) { r.Secret = []byte("private") }, func(r *Request) { r.Operation = &control.UserOperation{} }, func(r *Request) { r.AppCDField = &control.AppCDFieldRequest{App: "other"} }} {
			r := base
			alter(&r)
			if r.validMethodFields() || r.validQuerySelectors() {
				t.Fatal("foreign selector accepted", method)
			}
		}
		foreign := base
		foreign.Method = "tasks"
		if foreign.validMethodFields() || foreign.validQuerySelectors() {
			t.Fatal("CD read payload accepted by tasks")
		}
	}
}

func TestCDSnapshotCollectorRejectsChangedDigestAndExactPartLength(t *testing.T) {
	raw := make([]byte, deployment.ArtifactPartBytes+2)
	digest := sha256.Sum256(raw)
	read := func(part int, want [32]byte) (*control.AppCDSnapshotPart, error) {
		start := part * deployment.ArtifactPartBytes
		return &control.AppCDSnapshotPart{Schema: 1, Tenant: "tenant", App: "app", Kind: "diff", Part: part, Length: len(raw), Digest: digest, Data: raw[start:min(start+deployment.ArtifactPartBytes, len(raw))]}, nil
	}
	collected, err := collectCDSnapshot("tenant", "app", "diff", read)
	if err != nil || len(collected) != len(raw) {
		t.Fatal(err)
	}
	if _, err = collectCDSnapshot("tenant", "app", "diff", func(i int, d [32]byte) (*control.AppCDSnapshotPart, error) {
		p, e := read(i, d)
		if i == 1 {
			p.Digest = [32]byte{1}
		}
		return p, e
	}); err == nil {
		t.Fatal("mixed snapshot accepted")
	}
	if _, err = collectCDSnapshot("tenant", "app", "diff", func(i int, d [32]byte) (*control.AppCDSnapshotPart, error) {
		p, e := read(i, d)
		p.Data = p.Data[:len(p.Data)-1]
		return p, e
	}); err == nil {
		t.Fatal("short part accepted")
	}
}
