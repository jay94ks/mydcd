// SPDX-License-Identifier: Apache-2.0

package control

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"testing"

	"github.com/jay94ks/mydcd/internal/access"
	"github.com/jay94ks/mydcd/internal/cluster/state"
	"github.com/jay94ks/mydcd/internal/deployment"
)

// Only native outcomes are model inputs. Planning, exact upload, signed user
// acceptance, checkpoint retention and queries use the real product cores.
func acceptSourceVersion(t *testing.T, f *backupCoreFixture, id string, raw []byte) {
	t.Helper()
	plan, err := f.p.AppPlanArtifact(f.s, f.session, 10, "tenant", AppPlanRequest{Document: raw, Project: "source-view", Deployment: "deploy"})
	if err != nil {
		t.Fatal("plan original app document", err)
	}
	f.apply(id+"-upload", "begin-app-upload", 0, AppUploadBegin{Tenant: "tenant", App: "source-view", Deployment: "deploy", ID: id, Length: len(plan), Digest: sha256.Sum256(plan)}, state.Applied)
	for index, start := 0, 0; start < len(plan); index, start = index+1, start+deployment.ArtifactPartBytes {
		apps, _ := f.p.Apps(f.s)
		var revision uint64
		for _, upload := range apps.uploads {
			if upload.ID == id {
				revision = upload.Revision
			}
		}
		f.apply(fmt.Sprintf("%s-part-%d", id, index), "put-app-part", revision, AppUploadPart{Tenant: "tenant", ID: id, Index: index, Data: plan[start:min(start+deployment.ArtifactPartBytes, len(plan))]}, state.Applied)
	}
	apps, _ := f.p.Apps(f.s)
	inventory, found := apps.Inventory("tenant", "source-view")
	expected := uint64(0)
	if found {
		expected = inventory.Revision()
	}
	f.apply(id+"-accept", "begin-app", expected, AppBegin{Tenant: "tenant", App: "source-view", Deployment: "deploy", Upload: id, Operation: id}, state.Applied)
}

func TestAppSourceVersionsKeepExactBytesOldRevisionsAndCurrentReadScope(t *testing.T) {
	f := managedDNSTaskCoreFixture(t)
	raw := []byte("# " + string(bytes.Repeat([]byte{'a'}, 26000)) + "\nname: source-view\nservices:\n  web:\n    image: docker.io/library/php@sha256:" + string(bytes.Repeat([]byte{'a'}, 64)) + "\n    cpus: '0.1'\n    mem_limit: 16m\n    networks: {lan: {ipv4_address: 10.80.1.9}}\n    x-mydc: {node: node-a}\nnetworks:\n  lan: {external: true, name: services}\n")
	acceptSourceVersion(t, f, "run-source-view", raw)
	q := AppSourceSelection{App: "source-view", Deployment: "deploy"}
	first, err := f.p.AppSource(f.s, f.session, 10, "tenant", q)
	if err != nil || first.Version.Revision != 1 || first.Version.Digest != sha256.Sum256(raw) || first.Version.Length != len(raw) || len(first.Data) != deployment.ArtifactPartBytes || first.Version.SubmittedBy != "admin" || first.Version.Source != "upload" {
		t.Fatal("first accepted source", first.Version, err)
	}
	q.Revision, q.Part, q.Digest = 1, 1, first.Version.Digest
	rest, err := f.p.AppSource(f.s, f.session, 10, "tenant", q)
	if err != nil || !bytes.Equal(append(first.Data, rest.Data...), raw) {
		t.Fatal("source chunks lost exact original bytes", err)
	}
	first.Data[0] = '!'
	again, err := f.p.AppSource(f.s, f.session, 10, "tenant", AppSourceSelection{App: "source-view"})
	if err != nil || again.Data[0] != '#' {
		t.Fatal("source query aliases FSM metadata", err)
	}
	apps, _ := f.p.Apps(f.s)
	e, _ := apps.Execution("tenant", "source-view")
	for _, step := range e.Steps() {
		managedDNSTaskCoreSubmit(t, f, "source-view", step.Key, true, state.Applied)
	}
	managedDNSTaskCoreProgress(t, f, "source-view", "finish", "", nil)
	second := append(bytes.Clone(raw), []byte("\n# A new accepted document, same runtime intent.\n")...)
	acceptSourceVersion(t, f, "source-second", second)
	page, err := f.p.AppRevisions(f.s, f.session, 10, "tenant", AppSourceSelection{App: "source-view"}, "")
	if err != nil || len(page.Versions) != 2 || page.Versions[0].Revision != 2 || page.Versions[1].Revision != 1 || page.Versions[1].CompletedAt == 0 {
		t.Fatal("history numbering/completion", page, err)
	}
	checkpoint, encodeErr := state.Encode(f.s)
	if encodeErr != nil {
		t.Fatal(encodeErr)
	}
	restored, decodeErr := state.Decode(checkpoint)
	if decodeErr != nil {
		t.Fatal(decodeErr)
	}
	f.s = restored
	old, err := f.p.AppSource(f.s, f.session, 10, "tenant", AppSourceSelection{App: "source-view", Revision: 1})
	if err != nil || old.Version.Digest != sha256.Sum256(raw) {
		t.Fatal("previous source lost after new acceptance", err)
	}
	latest, err := f.p.AppSource(f.s, f.session, 10, "tenant", AppSourceSelection{App: "source-view"})
	if err != nil || latest.Version.Revision != 2 || latest.Version.Digest != sha256.Sum256(second) {
		t.Fatal("current original was not replaced atomically", err)
	}
	bad := AppSourceSelection{App: "source-view", Revision: 2, Part: 1, Digest: sha256.Sum256(raw)}
	if _, err := f.p.AppSource(f.s, f.session, 10, "tenant", bad); !errors.Is(err, access.ErrConflict) {
		t.Fatal("another version spliced into later part", err)
	}
	if _, err := f.p.AppSource(f.s, f.session, 10, "other", AppSourceSelection{App: "source-view"}); !errors.Is(err, access.ErrDenied) {
		t.Fatal("foreign tenant original exposed", err)
	}
	if _, err := f.p.AppSource(f.s, f.session, 10, "tenant", AppSourceSelection{App: "source-view", Deployment: "wrong"}); !errors.Is(err, access.ErrDenied) {
		t.Fatal("deployment identity ignored", err)
	}
	cursor := nextTaskCursor(appSourceBasis(f.s, f.session, "tenant", AppSourceSelection{App: "source-view"}), 0)
	if _, err := f.p.AppRevisions(f.s, f.session, 10, "tenant", AppSourceSelection{App: "source-view", Deployment: "deploy"}, cursor); !errors.Is(err, access.ErrConflict) {
		t.Fatal("version cursor changed selector", err)
	}
}

func TestLegacyAppOriginalIsExplicitlyUnavailable(t *testing.T) {
	f, _, _ := logClearPlanFixture(t, "local")
	q := AppSourceSelection{App: "source-app"}
	page, err := f.p.AppRevisions(f.s, f.session, 10, "tenant", q, "")
	if err != nil || len(page.Versions) != 1 || page.Versions[0].OriginalRetained || page.Versions[0].Digest != ([32]byte{}) {
		t.Fatal("legacy metadata masqueraded as original bytes", page, err)
	}
	if _, err := f.p.AppSource(f.s, f.session, 10, "tenant", q); !errors.Is(err, ErrAppSourceUnavailable) {
		t.Fatal("reconstructed YAML substituted for original", err)
	}
}
