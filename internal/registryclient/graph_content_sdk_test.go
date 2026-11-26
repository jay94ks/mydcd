// SPDX-License-Identifier: Apache-2.0

package registryclient

import (
	"context"
	"crypto/sha256"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	oci "github.com/google/go-containerregistry/pkg/registry"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/random"
	"github.com/google/go-containerregistry/pkg/v1/remote"
)

// Actual pinned OCI SDK, HTTPS challenge and independent repository readers.
// No Docker/BuildKit process or shared policy is simulated as completed here.
func TestGraphContentBasicOnlyReadersOnSameHostRemainIndependent(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	backend := oci.New(oci.Logger(log.New(io.Discard, "", 0)))
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, password, ok := r.BasicAuth()
		allowed := user == "one" || user == "two"
		if strings.HasPrefix(r.URL.Path, "/v2/team/one/") {
			allowed = user == "one"
		} else if strings.HasPrefix(r.URL.Path, "/v2/team/two/") {
			allowed = user == "two"
		}
		if !ok || !allowed || password != "private-"+user {
			w.Header().Set("WWW-Authenticate", `Basic realm="private"`)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		backend.ServeHTTP(w, r)
	}))
	defer server.Close()
	authority := strings.TrimPrefix(server.URL, "https://")
	ca := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})
	for _, user := range []string{"one", "two"} {
		image, err := random.Image(16<<10, 1)
		if err != nil {
			t.Fatal(err)
		}
		index := mutate.AppendManifests(empty.Index, mutate.IndexAddendum{Add: image})
		tag, err := name.NewTag(authority+"/team/"+user+":stable", name.StrictValidation)
		if err != nil {
			t.Fatal(err)
		}
		opts := []remote.Option{remote.WithContext(ctx), remote.WithAuth(authn.FromConfig(authn.AuthConfig{Username: user, Password: "private-" + user})), remote.WithTransport(server.Client().Transport), remote.WithJobs(1)}
		if err := remote.WriteIndex(tag, index, opts...); err != nil {
			t.Fatal(err)
		}
		root, err := index.Digest()
		if err != nil {
			t.Fatal(err)
		}
		child, err := image.Digest()
		if err != nil {
			t.Fatal(err)
		}
		manifest, err := image.Manifest()
		if err != nil {
			t.Fatal(err)
		}
		client, err := New(authority, []byte(user), []byte("private-"+user), ca)
		if err != nil {
			t.Fatal(err)
		}
		defer client.Close()
		q := GraphContentQuery{Root: tag.Context().Name() + "@" + root.String(), Path: []string{child.String()}, Kind: "layer", Digest: manifest.Layers[0].Digest.String()}
		info, body, err := client.OpenGraphContent(ctx, q)
		if err != nil {
			t.Fatal(user, err)
		}
		data, err := io.ReadAll(io.LimitReader(body, info.Bytes+1))
		closed := body.Close()
		if err != nil || closed != nil || !info.Valid(q.Selected()) || int64(len(data)) != info.Bytes || fmt.Sprintf("sha256:%x", sha256.Sum256(data)) != info.Digest {
			t.Fatal("Basic reader lost selected content", user, info, err, closed)
		}
		other := "one"
		if user == "one" {
			other = "two"
		}
		wrong, err := New(authority, []byte(other), []byte("private-"+other), ca)
		if err != nil {
			t.Fatal(err)
		}
		_, body, err = wrong.OpenGraphContent(ctx, q)
		wrong.Close()
		if body != nil {
			_ = body.Close()
		}
		if err == nil || body != nil {
			t.Fatal("same-host credentials crossed repositories", user, err)
		}
	}
}
