// SPDX-License-Identifier: Apache-2.0

package userauth

import (
	"encoding/base64"
	"strings"
	"testing"

	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/imagebuild"
)

func TestBuildContentQuerySelectorsAndCursorRejectCrossMethodInput(t *testing.T) {
	q := imagebuild.ContentQuery{Version: [32]byte{1}, Part: "tree"}
	root := [32]byte{2}
	cursor := base64.RawURLEncoding.EncodeToString(append(append([]byte{1}, root[:]...), []byte("0000000008")...))
	r := BuildContextContentQuery{Tenant: "tenant", Query: q, After: cursor}
	if !r.Valid() {
		t.Fatal("valid content cursor rejected")
	}
	for _, bad := range []BuildContextContentQuery{{Query: q, After: cursor}, {Tenant: "tenant", Query: q, After: strings.Repeat("a", 513)}, {Tenant: "tenant", After: cursor}} {
		if bad.Valid() {
			t.Fatal("invalid content selector accepted", bad)
		}
	}
	for _, raw := range []string{
		`{"Tenant":"tenant","Query":{"Version":[1,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],"Part":"tree"},"Node":"other"}`,
		`{"Tenant":"tenant","Query":{"Part":"tree"},"Secret":"c2VjcmV0"}`,
		`{"Tenant":"tenant","Query":{"Part":"tree"},"ImageBuild":{"Part":"contexts"}}`,
	} {
		if strict([]byte(raw), &BuildContextContentQuery{}) == nil {
			t.Fatal("foreign content field accepted", raw)
		}
	}
	metadata := ImageBuildsQuery{Tenant: "tenant", Query: control.ImageBuildQuery{Part: "contexts"}, After: cursor}
	if !metadata.Valid() {
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
	base := ImageBuildsQuery{Tenant: "tenant", Query: control.ImageBuildQuery{Part: "contexts"}}
	if !base.Valid() {
		t.Fatal("valid metadata request rejected")
	}
	if (ImageBuildsQuery{Tenant: "tenant", Query: control.ImageBuildQuery{Part: "missing"}}).Valid() {
		t.Fatal("missing upload selector")
	}
	for _, raw := range []string{
		`{"Tenant":"tenant","Query":{"Part":"contexts"},"Secret":"c2VjcmV0"}`,
		`{"Tenant":"tenant","Query":{"Part":"contexts"},"Node":"other"}`,
		`{"Tenant":"tenant","Query":{"Part":"contexts"},"Operation":{}}`,
	} {
		if strict([]byte(raw), &ImageBuildsQuery{}) == nil {
			t.Fatal("foreign metadata field accepted", raw)
		}
	}
}

func TestImageBuildJobPlanAndHistorySelectorsStaySeparate(t *testing.T) {
	q := control.ImageBuildJobQuery{ID: "build-one", Context: "source", Version: [32]byte{1}}
	r := ImageBuildJobPlanQuery{Tenant: "tenant", Query: q}
	if !r.Valid() {
		t.Fatal("valid job plan rejected")
	}
	if (ImageBuildJobPlanQuery{Query: q}).Valid() || (ImageBuildJobPlanQuery{Tenant: "tenant"}).Valid() {
		t.Fatal("job plan without tenant or job accepted")
	}
	for _, raw := range []string{
		`{"Tenant":"tenant","Query":{"ID":"build-one","Context":"source"},"After":"cursor"}`,
		`{"Tenant":"tenant","Query":{"ID":"build-one","Context":"source"},"Secret":"cGFzc3dvcmQ="}`,
	} {
		if strict([]byte(raw), &ImageBuildJobPlanQuery{}) == nil {
			t.Fatal("foreign job plan field accepted", raw)
		}
	}
	for _, q := range []control.ImageBuildQuery{{Part: "jobs"}, {Part: "jobs", ID: "source"}, {Part: "jobs", Job: "build-one"}} {
		if !(ImageBuildsQuery{Tenant: "tenant", Query: q}).Valid() {
			t.Fatal(q)
		}
	}
	if (control.ImageBuildQuery{Part: "contexts", Job: "build-one"}).Valid() || (control.ImageBuildQuery{Part: "jobs", Upload: "upload"}).Valid() {
		t.Fatal("unrelated upload/job selector accepted")
	}
}

func TestBuildSourceReadOnlyRequestCannotSelectAnotherRepository(t *testing.T) {
	if !(CheckBuildContextQuery{Tenant: "tenant", Query: control.ImageBuildSourceQuery{ID: "source"}}).Valid() {
		t.Fatal("registered source request rejected")
	}
	for _, raw := range []string{
		`{"Tenant":"tenant","Query":{"ID":"source"},"Secret":"b3ZlcnJpZGU="}`,
		`{"Tenant":"tenant","Query":{"ID":"source"},"ImageBuild":{"Part":"contexts"}}`,
		`{"Tenant":"tenant","Query":{"ID":"source","Repository":"https://other.example/repo.git"}}`,
	} {
		if strict([]byte(raw), &CheckBuildContextQuery{}) == nil {
			t.Fatal("source query accepted foreign input", raw)
		}
	}
}

func TestBuildTransferShapeCannotSmuggleManagementOrRawSealInput(t *testing.T) {
	r := BuildZIPTransferQuery{Tenant: "tenant", Request: imagebuild.Transfer{Upload: "original", Kind: "seal", Expected: 1}}
	if !r.Valid() {
		t.Fatal("valid seal rejected")
	}
	other := r
	other.Request.Data = []byte("another body")
	if other.Valid() {
		t.Fatal("seal raw bytes accepted")
	}
	if strict([]byte(`{"Tenant":"tenant","Request":{"Upload":"original","Kind":"seal","Expected":1},"Operation":{}}`), &BuildZIPTransferQuery{}) == nil {
		t.Fatal("operation on transfer boundary")
	}
}
