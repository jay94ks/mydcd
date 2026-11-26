// SPDX-License-Identifier: Apache-2.0

package control

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/jay94ks/mydcd/internal/access"
	"github.com/jay94ks/mydcd/internal/deployment"
	"github.com/jay94ks/mydcd/internal/schema"
)

func TestAppPartMetadataUsesBoundedEnvelopeWithoutWideningOtherActions(t *testing.T) {
	data := bytes.Repeat([]byte("p"), deployment.ArtifactPartBytes)
	payload, _ := json.Marshal(AppUploadPart{Tenant: "tenant", ID: "candidate", Index: 2, Data: data})
	raw, _ := json.Marshal(ChangeDocument{Schema: 1, Action: "put-app-part", Expected: 3, Payload: payload})
	if len(raw) <= 32<<10 {
		t.Fatal("part does not exercise larger envelope")
	}
	change, err := InputChange(raw, "alice")
	if err != nil || CommandKey(change.Action) != AppsKey || !bytes.Equal(change.Payload, payload) {
		t.Fatal("canonical part", err)
	}
	if _, err = schema.Input[ChangeDocument](raw); err == nil {
		t.Fatal("ordinary schema metadata limit widened")
	}
	raw = bytes.Replace(raw, []byte(`"action":"put-app-part"`), []byte(`"action":"create-tenant"`), 1)
	if _, err = InputChange(raw, "alice"); err == nil {
		t.Fatal("larger budget reached unrelated action")
	}
	payload, _ = json.Marshal(AppUploadPart{Tenant: "tenant", ID: "candidate", Data: append(data, 'x')})
	raw, _ = json.Marshal(ChangeDocument{Schema: 1, Action: "put-app-part", Payload: payload})
	if _, err = InputChange(raw, "alice"); err == nil {
		t.Fatal("oversized decoded part accepted")
	}
	for _, payload := range []any{AppUploadBegin{Tenant: "tenant", App: "app", Deployment: "deploy", ID: "candidate", Length: 1, Digest: sha256.Sum256([]byte("x"))}, AppBegin{Tenant: "tenant", App: "app", Deployment: "deploy", Upload: "candidate", Operation: "rollout"}, AppUploadSelection{Tenant: "tenant", ID: "candidate", User: "retired-user"}, AppRetirementReplay{Tenant: "tenant", App: "app", Retirement: "stop", Key: "workload/cd/tenant/app/source", Phase: "delete", Command: [32]byte{1}}} {
		action := "begin-app-upload"
		switch payload.(type) {
		case AppBegin:
			action = "begin-app"
		case AppUploadSelection:
			action = "abort-app-upload"
		case AppRetirementReplay:
			action = "resume-app-retirement"
		}
		p, _ := json.Marshal(payload)
		doc, _ := json.Marshal(ChangeDocument{Schema: 1, Action: action, Payload: p})
		if ch, e := InputChange(doc, "alice"); e != nil || ch.Principal != "alice" || CommandKey(action) != AppsKey {
			t.Fatal("typed app command", action, e)
		}
	}
}

func TestAppUploadPagesAreBoundedAndScopedToStableUser(t *testing.T) {
	anchor := [32]byte{91}
	c, _ := access.New(anchor)
	var err error
	c, err = c.Enroll(anchor, access.User{ID: "admin", Username: "admin", Enabled: true, SystemAdmin: true, Credentials: []access.Credential{{ID: "key", Method: access.PrivateKey, PublicKey: anchor, Enabled: true}}})
	if err != nil {
		t.Fatal(err)
	}
	c, err = c.CreateTenant("admin", "tenant", 0)
	if err != nil {
		t.Fatal(err)
	}
	a := Apps{}
	for i := 0; i < 10; i++ {
		u, e := deployment.NewUpload("tenant", "app", "deploy", "admin", fmt.Sprintf("upload-%02d", i), deployment.ArtifactMaxBytes, sha256.Sum256([]byte("not-complete")))
		if e != nil {
			t.Fatal(e)
		}
		a.uploads = append(a.uploads, u)
	}
	foreign := a.uploads[0]
	foreign.User = "other"
	a.uploads = append(a.uploads, foreign)
	page, next, err := a.Uploads(c, "admin", "tenant", "")
	if err != nil || len(page) != 8 || next != "upload-07" {
		t.Fatal("page", len(page), next, err)
	}
	encoded, _ := json.Marshal(page)
	if len(encoded) > 24<<10 {
		t.Fatal("upload metadata exceeds reply budget", len(encoded))
	}
	page, next, err = a.Uploads(c, "admin", "tenant", next)
	if err != nil || len(page) != 2 || next != "" {
		t.Fatal("last page", len(page), next, err)
	}
	if _, _, err = a.Uploads(c, "unregistered", "tenant", ""); err == nil {
		t.Fatal("foreign user read upload")
	}
}
