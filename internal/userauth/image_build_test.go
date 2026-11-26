// SPDX-License-Identifier: Apache-2.0

package userauth

import (
	"encoding/base64"
	"strings"
	"testing"

	"github.com/jay94ks/mydcd/internal/cluster/control"
	"github.com/jay94ks/mydcd/internal/imagebuild"
)

func TestBuildContentQuerySelectorsAndCursorRejectCrossMethodInput(t *testing.T) {
	q := imagebuild.ContentQuery{Version: [32]byte{1}, Part: "tree"}
	root := [32]byte{2}
	cursor := base64.RawURLEncoding.EncodeToString(append(append([]byte{1}, root[:]...), []byte("0000000008")...))
	r := Request{Schema: 1, Method: "build-context-content", Tenant: "tenant", ImageBuildContent: &q, After: cursor}
	if !r.validMethodFields() || !r.validQuerySelectors() {
		t.Fatal("valid content cursor rejected")
	}
	for _, edit := range []func(*Request){
		func(r *Request) { r.Method = "whoami" }, func(r *Request) { r.Tenant = "" }, func(r *Request) { r.Node = "other" },
		func(r *Request) { r.Secret = []byte("secret") }, func(r *Request) { r.ImageBuild = &control.ImageBuildQuery{Part: "contexts"} },
		func(r *Request) { r.After = strings.Repeat("a", 513) }, func(r *Request) { r.ImageBuildContent = nil },
	} {
		bad := r
		edit(&bad)
		if bad.validMethodFields() || bad.validQuerySelectors() {
			t.Fatal("mixed content selector accepted", bad.Method)
		}
	}
	metadata := Request{Schema: 1, Method: "image-builds", Tenant: "tenant", ImageBuild: &control.ImageBuildQuery{Part: "contexts"}, After: cursor}
	if !metadata.validMethodFields() || !metadata.validQuerySelectors() {
		t.Fatal("metadata next page rejected")
	}
}

func TestBuildContentClientRejectsMissingTrailingAndForeignPageEvidence(t *testing.T) {
	q := imagebuild.ContentQuery{Version: [32]byte{1}, Part: "dockerfile"}
	page := control.ImageBuildContentPage{Page: imagebuild.ContentPage{Schema: 1, Version: q.Version, Tree: [32]byte{2}, Part: q.Part, Total: 4, Data: []byte("text")}, Root: [32]byte{3}, Epoch: 1}
	if !validBuildContentPage(page, q, 0, [32]byte{}) {
		t.Fatal("valid terminal page rejected")
	}
	for _, edit := range []func(*control.ImageBuildContentPage){
		func(p *control.ImageBuildContentPage) { p.Page.Data = p.Page.Data[:3] }, func(p *control.ImageBuildContentPage) { p.Next = "trailing" },
		func(p *control.ImageBuildContentPage) { p.Page.Tree = [32]byte{} }, func(p *control.ImageBuildContentPage) { p.Root = [32]byte{} },
		func(p *control.ImageBuildContentPage) { p.Page.Version[0]++ }, func(p *control.ImageBuildContentPage) { p.Epoch = 0 },
	} {
		bad := page
		edit(&bad)
		if validBuildContentPage(bad, q, 0, [32]byte{}) {
			t.Fatal("corrupt owner evidence accepted")
		}
	}
	if validBuildContentPage(page, q, 0, [32]byte{9}) || validBuildContentPage(page, q, 1, page.Root) {
		t.Fatal("foreign snapshot/offset accepted")
	}
}

func TestImageBuildRequestShapeKeepsUnrelatedSelectorsOut(t *testing.T) {
	base := Request{Schema: 1, Method: "image-builds", Tenant: "tenant", ImageBuild: &control.ImageBuildQuery{Part: "contexts"}, Nonce: [32]byte{1}}
	if !base.validMethodFields() {
		t.Fatal("valid metadata request rejected")
	}
	other := base
	other.Method = "whoami"
	if other.validMethodFields() {
		t.Fatal("build selector accepted on another method")
	}
	other = base
	other.Secret = []byte("secret")
	if other.validMethodFields() {
		t.Fatal("raw private input on metadata query")
	}
	other = base
	other.Node = "other"
	if other.validMethodFields() {
		t.Fatal("unrelated node selector")
	}
	other = base
	other.ImageBuild = &control.ImageBuildQuery{Part: "missing"}
	if other.validMethodFields() {
		t.Fatal("missing upload selector")
	}
	other = base
	other.Operation = &control.UserOperation{}
	if other.validMethodFields() {
		t.Fatal("operation injected through read request")
	}
}

func TestImageBuildJobPlanAndHistorySelectorsStaySeparate(t *testing.T) {
	q := control.ImageBuildJobQuery{ID: "build-one", Context: "source", Version: [32]byte{1}}
	r := Request{Schema: 1, Method: "image-build-job-plan", Tenant: "tenant", ImageBuildJob: &q}
	if !r.validMethodFields() || !r.validQuerySelectors() {
		t.Fatal("valid job plan rejected")
	}
	for _, edit := range []func(*Request){func(r *Request) { r.Method = "whoami" }, func(r *Request) { r.Tenant = "" }, func(r *Request) { r.Node = "other" }, func(r *Request) { r.After = "cursor" }, func(r *Request) { r.Secret = []byte("password") }, func(r *Request) { r.ImageBuildJob = nil }} {
		bad := r
		edit(&bad)
		if bad.validMethodFields() || bad.validQuerySelectors() {
			t.Fatal("mixed build plan accepted", bad.Method)
		}
	}
	for _, q := range []control.ImageBuildQuery{{Part: "jobs"}, {Part: "jobs", ID: "source"}, {Part: "jobs", Job: "build-one"}} {
		r := Request{Schema: 1, Method: "image-builds", Tenant: "tenant", ImageBuild: &q}
		if !r.validMethodFields() || !r.validQuerySelectors() {
			t.Fatal(q)
		}
	}
	if (control.ImageBuildQuery{Part: "contexts", Job: "build-one"}).Valid() || (control.ImageBuildQuery{Part: "jobs", Upload: "upload"}).Valid() {
		t.Fatal("unrelated upload/job selector accepted")
	}
}

func TestBuildSourceReadOnlyRequestCannotSelectAnotherRepository(t *testing.T) {
	r := Request{Schema: 1, Method: "check-build-context", Tenant: "tenant", ImageBuildSource: &control.ImageBuildSourceQuery{ID: "source"}, Nonce: [32]byte{1}}
	if !r.validMethodFields() {
		t.Fatal("registered source request rejected")
	}
	other := r
	other.Secret = []byte("override credential")
	if other.validMethodFields() {
		t.Fatal("source query injects credentials")
	}
	other = r
	other.ImageBuild = &control.ImageBuildQuery{Part: "contexts"}
	if other.validMethodFields() {
		t.Fatal("source query injects another selector")
	}
}

func TestBuildTransferShapeCannotSmuggleManagementOrRawSealInput(t *testing.T) {
	r := Request{Schema: 1, Method: "build-zip-transfer", Tenant: "tenant", ImageBuildTransfer: &imagebuild.Transfer{Upload: "original", Kind: "seal", Expected: 1}, Nonce: [32]byte{1}}
	if !r.validMethodFields() {
		t.Fatal("valid seal rejected")
	}
	other := r
	other.Operation = &control.UserOperation{}
	if other.validMethodFields() {
		t.Fatal("operation on transfer boundary")
	}
	q := *r.ImageBuildTransfer
	q.Data = []byte("another body")
	other = r
	other.ImageBuildTransfer = &q
	if other.validMethodFields() {
		t.Fatal("seal raw bytes accepted")
	}
	other = r
	other.Method = "image-builds"
	if other.validMethodFields() {
		t.Fatal("transfer used as a metadata selector")
	}
}
