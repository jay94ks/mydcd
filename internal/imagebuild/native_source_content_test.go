// SPDX-License-Identifier: Apache-2.0

package imagebuild

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/jay94ks/mydcd/internal/registryclient"
)

func TestSourceContentModeIsFixedByOriginalNativeJournalAndKeepsLegacyJSON(t *testing.T) {
	f := newNativeFixture(t, false)
	if err := f.jobs.UseSDK(f.ctx(), f.spec); err != nil {
		t.Fatal(err)
	}
	r, err := f.jobs.Record(f.spec)
	if err != nil || r.Solve == nil || !r.Solve.SourceContent || !r.Solve.TLS {
		t.Fatal("new SDK job did not select owner content", err)
	}
	f.jobs.mu.Lock()
	old, err := f.jobs.load(f.spec)
	if err == nil {
		old.Solve.SourceContent = false
		err = f.jobs.save(old)
	}
	f.jobs.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	f.reopen()
	if err := f.jobs.UseSDK(f.ctx(), f.spec); err != nil {
		t.Fatal(err)
	}
	r, err = f.jobs.Record(f.spec)
	if err != nil || r.Solve.SourceContent {
		t.Fatal("existing original SDK mode was silently upgraded", err)
	}
	current, _ := json.Marshal(NativeSolve{TLS: true})
	legacy, _ := json.Marshal(struct {
		Sent, Returned, Stopping bool
		Code                     string
		Directory                NativeDirectory
		TLS                      bool      `json:",omitempty"`
		Trust                    *[32]byte `json:",omitempty"`
	}{TLS: true})
	if !bytes.Equal(current, legacy) {
		t.Fatal("absent source mode changed original schema1 bytes")
	}
}

func TestOwnerContentDaemonControlsDoNotImportOrMergeSourceCAs(t *testing.T) {
	f := newNativeFixture(t, false)
	ctx := f.ctx()
	if err := f.jobs.UseSDK(ctx, f.spec); err != nil {
		t.Fatal(err)
	}
	options, err := f.plan.createOptionsWithTLS(f.spec, true, true)
	if err != nil {
		t.Fatal(err)
	}
	f.edit(func() { f.options = options })
	f.grant.Run.Inputs = []FrozenSource{sourceStoreFixtureFor(t).input}
	f.prepare(ctx)
	r, err := f.jobs.Record(f.spec)
	_, emptyTrust, cause := buildTrustControls(nil, nil)
	if err != nil || cause != nil || r.Solve.Trust == nil || *r.Solve.Trust != emptyTrust {
		t.Fatal("source CAs were required by owner-content daemon", err, cause)
	}
	if err := f.jobs.StageControlsTLS(ctx, f.spec, nil, []registryclient.RegistryTrust{{Authority: "registry.example"}}); err == nil {
		t.Fatal("daemon accepted unrelated source trust in owner-content mode")
	}
}
