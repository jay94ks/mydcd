// SPDX-License-Identifier: Apache-2.0

package userauth

import (
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/google/go-containerregistry/pkg/v1/types"
	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/imagebuild"
	"github.com/jay94ks/seafield/internal/registryclient"
	"github.com/jay94ks/seafield/internal/schema"
	"github.com/jay94ks/seafield/internal/sfcp"
)

// Uses actual member QUIC and the production finite sender/receiver. Source
// authority is injected; signed begin/current policy is tested in control.
func TestBuildBaseContentMemberStreamDoesNotRequireOrMintAUserSession(t *testing.T) {
	for _, mode := range []string{"ok", "truncated", "extra", "corrupt", "revoked"} {
		t.Run(mode, func(t *testing.T) {
			_, c, _, node := journalFixture(t)
			owner := c.Peers[0]
			owner.Member = true
			lookup := func(key sfcp.Identity) (sfcp.Peer, bool) {
				if key == sfcp.Identity(c.Self.Public) {
					return sfcp.Peer{ID: "builder", Policy: sfcp.Policy{Key: key, Member: true, Respond: true}}, true
				}
				return owner, key == owner.Key
			}
			server, err := sfcp.NewTransport(node, c.Cluster, lookup)
			if err != nil {
				t.Fatal(err)
			}
			defer server.Close()
			mesh, err := sfcp.NewTransport(c.Self, c.Cluster, lookup)
			if err != nil {
				t.Fatal(err)
			}
			defer mesh.Close()
			c.Mesh = mesh
			payload := bytes.Repeat([]byte("accepted-source-layer"), 4000)
			q := registryclient.GraphContentQuery{Root: "registry.example/team/app@sha256:" + strings.Repeat("a", 64), Path: []string{"sha256:" + strings.Repeat("b", 64)}, Kind: "layer", Digest: fmt.Sprintf("sha256:%x", sha256.Sum256(payload))}
			read := control.ImageBuildBaseContentRead{Read: control.ImageBuildBaseRead{Cluster: c.Cluster, Builder: c.Self.Public, Query: control.ImageBuildBaseQuery{Tenant: "tenant", Job: "build", Snapshot: [32]byte{1}, At: 1, Source: imagebuild.Source{Reference: "registry.example/team/app:latest", Platform: "linux/amd64", Kind: "from"}}, Target: control.ImageResolveTarget{Owner: node.Public, Normalized: q.Root}}, Query: q}
			selected := q.Selected()
			info := registryclient.ContentInfo{Schema: 1, Ref: selected.Ref, Kind: q.Kind, Digest: q.Digest, MediaType: string(types.OCILayer), Bytes: int64(len(payload))}
			body := bytes.Clone(payload)
			switch mode {
			case "truncated":
				body = body[:len(body)-1]
			case "extra":
				body = append(body, 'x')
			case "corrupt":
				body[0] ^= 1
			}
			finished := make(chan error, 1)
			if err = server.OnManagement(sfcp.ImageContent, func(ctx context.Context, conn *sfcp.Session, stream sfcp.Stream, frame sfcp.Frame) error {
				result := func() error {
					envelope, err := schema.Decode[Envelope](frame.Fields[0].Value)
					if err != nil || envelope.Session != nil || envelope.Relay != nil || len(envelope.Signature) != 0 {
						return sfcp.ErrFrame
					}
					request, err := schema.Decode[ImageBuildBaseContentRequest](envelope.Body)
					if err != nil || !request.valid(time.Now().Unix()) || frame.Kind != sfcp.KindImageSourceRead || request.Read.Read.Builder != [32]byte(conn.Peer().Key) || request.Read.Query.Selected() != selected || conn.Admit(frame, sfcp.ImageContent, false) != nil {
						return sfcp.ErrAdmission
					}
					if err := streamEOF(stream); err != nil {
						return err
					}
					calls := 0
					source := ImageContentSource{Info: info, Body: io.NopCloser(bytes.NewReader(body)), Authorize: func(context.Context) error {
						calls++
						if mode == "revoked" && calls > 1 {
							return sfcp.ErrAdmission
						}
						return nil
					}}
					defer source.Body.Close()
					return sendImageContent(ctx, stream, frame, sha256.Sum256(frame.Fields[0].Value), source)
				}()
				finished <- result
				return result
			}); err != nil {
				t.Fatal(err)
			}
			if err := server.Listen("127.0.0.1:0"); err != nil {
				t.Fatal(err)
			}
			owner.Endpoint = server.Addr().String()
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			var output bytes.Buffer
			got, err := c.ReadImageBuildBaseContent(ctx, owner, read, &output)
			if mode == "ok" {
				if err != nil || got != info || !bytes.Equal(output.Bytes(), payload) {
					t.Fatal("original member content lost", got, err)
				}
			} else if err == nil {
				t.Fatal("unverified member content accepted", mode)
			}
			select {
			case err := <-finished:
				if err != nil {
					t.Fatal(err)
				}
			case <-ctx.Done():
				t.Fatal("member body sender did not finish", ctx.Err())
			}
		})
	}
}
