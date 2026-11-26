// SPDX-License-Identifier: Apache-2.0

package registryclient

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	oci "github.com/google/go-containerregistry/pkg/registry"
	"github.com/google/go-containerregistry/pkg/v1/random"
	"github.com/google/go-containerregistry/pkg/v1/remote"
)

func TestExternalCatalogueUsesSameScopedTLSAndReturnsOnlyAuthorizedNames(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	backend := oci.New(oci.Logger(log.New(io.Discard, "", 0)))
	var status atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, password, ok := r.BasicAuth()
		if !ok || user != "reader" || password != "private-password" {
			w.Header().Set("WWW-Authenticate", `Basic realm="private"`)
			w.WriteHeader(401)
			return
		}
		if status.Load() != 0 && strings.Contains(r.URL.Path, "/_catalog") {
			http.Error(w, "private-body", int(status.Load()))
			return
		}
		backend.ServeHTTP(w, r)
	}))
	defer server.Close()
	authority := strings.TrimPrefix(server.URL, "https://")
	image, err := random.Image(1024, 1)
	if err != nil {
		t.Fatal(err)
	}
	options := []remote.Option{remote.WithContext(ctx), remote.WithAuth(authn.FromConfig(authn.AuthConfig{Username: "reader", Password: "private-password"})), remote.WithTransport(server.Client().Transport), remote.WithJobs(1)}
	for i := 0; i < 9; i++ {
		tag, err := name.NewTag(fmt.Sprintf("%s/team/app:tag%d", authority, i), name.StrictValidation)
		if err != nil {
			t.Fatal(err)
		}
		if err = remote.Write(tag, image, options...); err != nil {
			t.Fatal(err)
		}
	}
	foreign, _ := name.NewTag(authority+"/foreign/hidden:tag", name.StrictValidation)
	if err = remote.Write(foreign, image, options...); err != nil {
		t.Fatal(err)
	}
	ca := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})
	access, err := New(authority, []byte("reader"), []byte("private-password"), ca)
	if err != nil {
		t.Fatal(err)
	}
	defer access.Close()
	allow := func(repo string) bool { return repo == "team/app" }
	repos, err := access.Catalogue(ctx, "", [32]byte{1}, "", allow)
	if err != nil || len(repos.Repositories) != 1 || repos.Repositories[0] != "team/app" || !repos.Live || repos.UntaggedComplete || !repos.Valid(authority, "", "") {
		t.Fatal(repos, err)
	}
	page, err := access.Catalogue(ctx, "team/app", [32]byte{1}, "", allow)
	if err != nil || len(page.Images) != 8 || page.Next == "" || !page.Valid(authority, "team/app", "") {
		t.Fatal(page, err)
	}
	for _, row := range page.Images {
		if row.ImageBytes <= 0 || row.UploadedAtKnown || row.UploadedAt != 0 {
			t.Fatal("invented external time/size", row)
		}
	}
	next, err := access.Catalogue(ctx, "team/app", [32]byte{1}, page.Next, allow)
	if err != nil || len(next.Images) != 1 || next.Next != "" || !next.Valid(authority, "team/app", page.Next) {
		t.Fatal(next, err)
	}
	if _, err = access.Catalogue(ctx, "foreign/hidden", [32]byte{1}, "", allow); err == nil || ResultCode(err) != "DENIED" {
		t.Fatal("foreign repository admitted", err)
	}
	newTag, _ := name.NewTag(authority+"/team/app:added", name.StrictValidation)
	if err = remote.Write(newTag, image, options...); err != nil {
		t.Fatal(err)
	}
	if _, err = access.Catalogue(ctx, "team/app", [32]byte{1}, page.Next, allow); err != ErrCatalogueChanged {
		t.Fatal("external name cursor did not change", err)
	}
	for _, code := range []int{403, 405} {
		status.Store(int32(code))
		_, err = access.Catalogue(ctx, "", [32]byte{1}, "", allow)
		want := "DENIED"
		if code == 405 {
			want = "UNSUPPORTED"
		}
		if err == nil || ResultCode(err) != want {
			t.Fatal(code, err)
		}
	}
	raw, _ := json.Marshal(page)
	for _, secret := range []string{"private-password", "private-body", "foreign/hidden", "Authorization"} {
		if strings.Contains(string(raw), secret) {
			t.Fatal("catalogue leaked private data", secret)
		}
	}
}

func TestCatalogueCursorNamesAndImmutableFieldsAreBounded(t *testing.T) {
	names := []string{}
	for i := 0; i < 9; i++ {
		names = append(names, fmt.Sprintf("team/app%d", i))
	}
	page, selected, err := CatalogueRange("registry.example", "", [32]byte{1}, names, nil, "")
	page.Repositories = selected
	if err != nil || len(selected) != 8 || !page.Valid("registry.example", "", "") {
		t.Fatal(page, err)
	}
	if _, _, err = CatalogueRange("registry.example", "", [32]byte{2}, names, nil, page.Next); err != ErrCatalogueChanged {
		t.Fatal("source/user selection not bound", err)
	}
	for _, repo := range []string{"../escape", "authority:443/repo", "UPPER/repo", "https://host/repo", "team/app:tag"} {
		if ValidRepository(repo) {
			t.Fatal("not an exact repository", repo)
		}
	}
	page.Next = "forged"
	if page.Valid("registry.example", "", "") {
		t.Fatal("invalid cursor accepted")
	}
	if _, _, err = CatalogueCursor(strings.Repeat("x", 513)); err == nil {
		t.Fatal("unbounded cursor")
	}
}
