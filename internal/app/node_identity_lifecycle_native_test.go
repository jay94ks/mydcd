// SPDX-License-Identifier: Apache-2.0

package app

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"os"

	"gopkg.in/yaml.v3"
	"testing"

	"github.com/jay94ks/seafield/internal/access"
	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/cluster/state"
	"github.com/jay94ks/seafield/internal/deployment"
	"github.com/jay94ks/seafield/internal/sfcp"
	"github.com/jay94ks/seafield/internal/userauth"
	checker "github.com/jay94ks/seafield/internal/workload/lifecycle"
	contract "github.com/jay94ks/seafield/lifecycle/v1"
)

// Runs within the existing installed-identity native fixture and its rollback.
// It adds real SFCP/editor/SourceStore reads, not another process or compiler.
func prepareIdentityLifecycleReadback(t *testing.T, ctx context.Context, user *userauth.Client, peer *sfcp.Peer, session *access.Session, node string, compiled ...bool) func() {
	t.Helper()
	change := func(id, action string, expected uint64, payload any) {
		t.Helper()
		raw, err := control.ChangeBytes(action, "admin", expected, payload)
		if err != nil {
			t.Fatal(err)
		}
		var q control.Change
		if err = json.Unmarshal(raw, &q); err != nil {
			t.Fatal(err)
		}
		op, err := user.Prepare(ctx, *peer, *session, id, q)
		if err != nil {
			t.Fatal(err)
		}
		result, err := user.Operation(ctx, *peer, op, false)
		if err != nil || result.Result == nil || result.Result.Code != state.Applied {
			t.Fatal("identity lifecycle change", id, result.Code, err)
		}
	}
	policy := checker.TenantPolicy{Tenant: "tenant", Enabled: true, Execution: checker.ExecutionPolicy{MaxConcurrent: 1, TimeoutMS: 5000, NanoCPU: 100000000, MemoryBytes: 64 << 20, MaxPIDs: 32, OutputBytes: 4096, ProbeBytes: 4096, Capabilities: []string{"file"}}, Resolver: checker.ResolverPolicy{AllowPackages: []string{"context", "github.com/jay94ks/seafield/lifecycle/v1"}, SourceCacheBytes: 1 << 20}}
	compile := len(compiled) != 0 && compiled[0]
	if !compile {
		change("identity-source-policy", "set-lifecycle-policy", 0, policy)
	} // Compiled mode retains the initial actual compiler policy and trust.
	text := []byte(`package checker
import (
 "context"
 lifecycle "github.com/jay94ks/seafield/lifecycle/v1"
)
func Check(ctx context.Context,in lifecycle.Request,probe lifecycle.Probe)(lifecycle.Result,error){
 return lifecycle.Result{Schema:1,Status:"pass",Reason:"retained-source"},nil
}
`)
	if compile {
		text = []byte(managedCheckerEndpointSource)
	}
	d, err := (checker.Script{Source: string(text)}).Descriptor("tenant")
	if err != nil {
		t.Fatal(err)
	}
	first := sha256.Sum256([]byte("identity-source-published"))
	staged, err := user.StageLifecycleSource(ctx, *peer, *session, node, d, first, text)
	if err != nil || staged.Source == nil {
		t.Fatal("original lifecycle editor", err)
	}
	original := staged.Source.Clone()
	change("identity-source-register", "put-lifecycle-script", 0, control.LifecycleScriptPut{Tenant: "tenant", Name: "identity-original", Source: original})
	pendingID := sha256.Sum256([]byte("identity-source-unsettled"))
	pending, err := user.StageLifecycleSource(ctx, *peer, *session, node, d, pendingID, text)
	if err != nil || pending.Source == nil {
		t.Fatal("original unpublished source", err)
	}
	before, err := user.LifecycleSource(ctx, *peer, *session, "tenant", "identity-original", 1)
	if err != nil || before.Source != string(text) {
		t.Fatal("source before identity switch", err)
	}
	return func() {
		t.Helper()
		after, err := user.LifecycleSource(ctx, *peer, *session, "tenant", "identity-original", 1)
		if err != nil || after.Source != before.Source || after.Digest != before.Digest {
			t.Fatal("current TLS cannot read exact original source version", err)
		}
		recovered, err := user.RecoverLifecycleSource(ctx, *peer, *session, node, d, pendingID)
		if err != nil || recovered.Source == nil || recovered.Owner != original.Owner || !bytes.Equal(recovered.Source.Signature, pending.Source.Signature) {
			t.Fatal("original upload recovery changed owner/proof", err)
		}
		nextID := sha256.Sum256([]byte("identity-source-current"))
		current, err := user.StageLifecycleSource(ctx, *peer, *session, node, d, nextID, text)
		if err != nil || current.Source == nil || current.Owner == original.Owner || current.Owner != [32]byte(peer.Key) {
			t.Fatal("new editor used retired source signer", err)
		}
		// Retrying the old stage must not create a same-ID hold in the new owner.
		if _, err = user.StageLifecycleSource(ctx, *peer, *session, node, d, pendingID, text); err == nil {
			t.Fatal("old upload allocated again after rotation")
		}
		if _, err = user.RecoverLifecycleSource(ctx, *peer, *session, node, d, sha256.Sum256([]byte("never-accepted"))); err == nil {
			t.Fatal("missing original recovery created content")
		}

	}
}

// The replacement Task explicitly references the original registered version.
// It must fetch/consume those bytes through the existing artifact core under
// its new current owner, rather than rewriting the SourceFact or old cache.
func attachIdentityLifecycleReadback(t *testing.T, path string, compiled ...bool) {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	input, err := deployment.ParseApp(raw)
	if err != nil {
		t.Fatal(err)
	}
	compile := len(compiled) != 0 && compiled[0]
	script := checker.Script{Ref: &checker.NamedReference{Name: "identity-original", Revision: 1}}
	if compile {
		script.Compile = &compile
	}
	input.Sfc.Lifecycle = &deployment.LifecycleDeclaration{Scripts: map[string]checker.Script{"identity-original": script}}
	service := input.Services["web"]
	service.Sfc.Lifecycle = &deployment.ServiceLifecycle{Checks: []deployment.LifecycleCheck{{ID: "identity-retained-source", Phase: contract.Readiness, Interval: "1s", Timeout: "3s", LifecycleTemplate: deployment.LifecycleTemplate{Script: "identity-original"}}}}
	input.Services["web"] = service
	raw, err = yaml.Marshal(input)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
}
