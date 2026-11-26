// SPDX-License-Identifier: Apache-2.0

package control

import (
	"bytes"
	"crypto/ed25519"
	"testing"

	"github.com/jay94ks/mydcd/internal/access"
	"github.com/jay94ks/mydcd/internal/cluster/state"
)

func TestCDTogglePreviewIsPureAndUsesSameRevisionAndOriginalInventory(t *testing.T) {
	f, _ := fieldCASFixture(t)
	before, err := state.Encode(f.s)
	if err != nil {
		t.Fatal(err)
	}
	pause, err := f.p.PlanCDToggle(f.s, f.session, 2, "tenant", CDToggleQuery{App: "source-app", Action: "pause-app-cd"})
	if err != nil || !pause.WouldPause || !pause.PreservesOriginal {
		t.Fatal("pause preview", err)
	}
	after, err := state.Encode(f.s)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("preview persisted a change", err)
	}
	managedDNSChange(t, f, "preview-pause", "pause-app-cd", pause.Expected, AppCDChange{Tenant: "tenant", App: "source-app"}, state.Applied)
	resume, err := f.p.PlanCDToggle(f.s, f.session, 2, "tenant", CDToggleQuery{App: "source-app", Action: "resume-app-cd"})
	if err != nil || !resume.Paused || resume.WouldPause || resume.ActiveOperation != pause.ActiveOperation {
		t.Fatal("resume replaced original operation", err)
	}
	managedDNSChange(t, f, "preview-resume", "resume-app-cd", resume.Expected, AppCDChange{Tenant: "tenant", App: "source-app"}, state.Applied)
	clipped := f.session
	clipped.Scopes = []access.Scope{{Tenant: "tenant", Actions: []access.Action{access.Read}}}
	clipped.Signature = ed25519.Sign(f.node, access.SessionBytes(clipped))
	if _, err = f.p.PlanCDToggle(f.s, clipped, 2, "tenant", CDToggleQuery{App: "source-app", Action: "pause-app-cd"}); err == nil {
		t.Fatal("reader previewed a management mutation")
	}
	if _, err = f.p.PlanCDToggle(f.s, f.session, 2, "foreign", CDToggleQuery{App: "source-app", Action: "pause-app-cd"}); err == nil {
		t.Fatal("foreign app planned")
	}
}
