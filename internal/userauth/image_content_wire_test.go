// SPDX-License-Identifier: Apache-2.0

package userauth

import (
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/go-containerregistry/pkg/v1/types"
	"github.com/jay94ks/mydcd/internal/cluster/control"
	"github.com/jay94ks/mydcd/internal/identity"
	"github.com/jay94ks/mydcd/internal/mydcp"
	"github.com/jay94ks/mydcd/internal/registryclient"
	"github.com/jay94ks/mydcd/internal/schema"
)

// Actual pinned TLS/Unix/QUIC and the production body sender/receiver. Only
// source authority/native selection are simulated here, not a second protocol.
func TestImageContentActualWireRejectsPartialCorruptAndOverlongBodies(t *testing.T) {
	for _, network := range []string{"unix", "quic"} {
		for _, mode := range []string{"ok", "truncated", "corrupt", "extra", "revoked"} {
			t.Run(network+"/"+mode, func(t *testing.T) {
				_, c, session, node := journalFixture(t)
				root, err := os.MkdirTemp("", "mydc-image-content-wire-")
				if err != nil {
					t.Fatal(err)
				}
				defer os.RemoveAll(root)
				peer := c.Peers[0]
				lookup := func(key mydcp.Identity) (mydcp.Peer, bool) {
					if key == mydcp.Identity(c.Self.Public) {
						return mydcp.Peer{ID: "user", Policy: mydcp.Policy{Key: key, UserAuth: true}}, true
					}
					return peer, key == peer.Key
				}
				server, err := mydcp.NewTransport(node, c.Cluster, lookup)
				if err != nil {
					t.Fatal(err)
				}
				defer server.Close()
				if network == "unix" {
					peer.Endpoint = "unix://" + filepath.Join(root, "api.sock")
				} else {
					if err = server.Listen("127.0.0.1:0"); err != nil {
						t.Fatal(err)
					}
					peer.Endpoint = server.Addr().String()
				}
				mesh, err := mydcp.NewTransport(c.Self, c.Cluster, lookup)
				if err != nil {
					t.Fatal(err)
				}
				defer mesh.Close()
				c.Mesh = mesh
				payload := bytes.Repeat([]byte("immutable-layer-content"), 4000)
				digest := fmt.Sprintf("sha256:%x", sha256.Sum256(payload))
				query := registryclient.ContentQuery{Ref: "registry.example/team/app@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", Kind: "layer", Digest: digest}
				info := registryclient.ContentInfo{Schema: 1, Ref: query.Ref, Kind: query.Kind, Digest: digest, MediaType: string(types.OCILayer), Bytes: int64(len(payload))}
				body := bytes.Clone(payload)
				switch mode {
				case "truncated":
					body = body[:len(body)-1]
				case "corrupt":
					body[0] ^= 1
				case "extra":
					body = append(body, 1)
				}
				binding := Service{Mesh: server, Self: node, Policy: control.Policy{Cluster: c.Cluster}}
				finished := make(chan error, 1)
				if err = server.OnManagement(mydcp.ImageContent, func(ctx context.Context, conn *mydcp.Session, stream mydcp.Stream, frame mydcp.Frame) error {
					result := func() error {
						envelope, err := schema.Decode[Envelope](frame.Fields[0].Value)
						if err != nil {
							return err
						}
						request, err := schema.Decode[ImageContentRequest](envelope.Body)
						if err != nil || !request.valid(time.Now().Unix()) || request.Query != query {
							return mydcp.ErrFrame
						}
						if _, err = binding.binding(conn, frame.Kind, envelope); err != nil {
							return err
						}
						if err = streamEOF(stream); err != nil {
							return err
						}
						calls := 0
						source := ImageContentSource{Info: info, Body: io.NopCloser(bytes.NewReader(body)), Authorize: func(context.Context) error {
							calls++
							if mode == "revoked" && calls > 1 {
								return mydcp.ErrAdmission
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
				if network == "unix" {
					if err = server.ListenUnix(filepath.Join(root, "api.sock")); err != nil {
						t.Fatal(err)
					}
				}
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				var output bytes.Buffer
				got, err := c.ReadImageContent(ctx, peer, session, "tenant", query, &output)
				if mode == "ok" {
					if err != nil || got != info || !bytes.Equal(output.Bytes(), payload) {
						t.Fatal("immutable body lost", got, err)
					}
				} else if err == nil {
					t.Fatal("incomplete/corrupt/revoked body accepted", mode)
				}
				select {
				case err := <-finished:
					if err != nil {
						t.Fatal("fixture protocol failed instead of a bounded result", err)
					}
				case <-ctx.Done():
					t.Fatal("original sender did not finish", ctx.Err())
				}
				if len(output.Bytes()) > len(payload) {
					t.Fatal("overlong source escaped declared body")
				}
			})
		}
	}
}

func TestImageContentUnixIngressRelaysOriginalUserProofToActualQUICOwner(t *testing.T) {
	_, c, session, node := journalFixture(t)
	// FromSeed also builds the TLS certificate; a bare Identity cannot
	// complete the owner's QUIC handshake.
	owner, err := identity.FromSeed(bytes.Repeat([]byte{93}, 32))
	if err != nil {
		t.Fatal(err)
	}
	root, err := os.MkdirTemp("", "mydc-image-content-relay-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(root)
	ingressPeer := mydcp.Peer{ID: "ingress", Endpoint: "unix://" + filepath.Join(root, "api.sock"), Policy: mydcp.Policy{Key: mydcp.Identity(node.Public), Respond: true, Member: true}}
	ownerPeer := mydcp.Peer{ID: "owner", Policy: mydcp.Policy{Key: mydcp.Identity(owner.Public), Respond: true, Member: true}}
	lookup := func(key mydcp.Identity) (mydcp.Peer, bool) {
		switch key {
		case mydcp.Identity(c.Self.Public):
			return mydcp.Peer{ID: "user", Policy: mydcp.Policy{Key: key, UserAuth: true}}, true
		case ingressPeer.Key:
			return ingressPeer, true
		case ownerPeer.Key:
			return ownerPeer, true
		}
		return mydcp.Peer{}, false
	}
	reader, err := mydcp.NewTransport(owner, c.Cluster, lookup)
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	if err = reader.Listen("127.0.0.1:0"); err != nil {
		t.Fatal(err)
	}
	ownerPeer.Endpoint = reader.Addr().String()
	ingress, err := mydcp.NewTransport(node, c.Cluster, lookup)
	if err != nil {
		t.Fatal(err)
	}
	defer ingress.Close()
	client, err := mydcp.NewTransport(c.Self, c.Cluster, lookup)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	c.Mesh = client
	payload := bytes.Repeat([]byte("owner-original-body"), 4000)
	digest := fmt.Sprintf("sha256:%x", sha256.Sum256(payload))
	q := registryclient.ContentQuery{Ref: "registry.example/team/app@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", Kind: "layer", Digest: digest}
	info := registryclient.ContentInfo{Schema: 1, Ref: q.Ref, Kind: q.Kind, Digest: digest, MediaType: string(types.OCILayer), Bytes: int64(len(payload))}
	ownerBinding := Service{Mesh: reader, Self: owner, Policy: control.Policy{Cluster: c.Cluster}}
	completed := make(chan error, 2)
	if err = reader.OnManagement(mydcp.ImageContent, func(ctx context.Context, conn *mydcp.Session, stream mydcp.Stream, frame mydcp.Frame) error {
		result := func() error {
			envelope, err := schema.Decode[Envelope](frame.Fields[0].Value)
			if err != nil || frame.Kind != 3 || envelope.Relay == nil || envelope.Relay.Node != node.Public || envelope.Relay.Target != owner.Public || envelope.Session == nil || !sameSession(*envelope.Session, session) {
				return mydcp.ErrAdmission
			}
			if _, err = ownerBinding.binding(conn, frame.Kind, envelope); err != nil {
				return err
			}
			request, err := schema.Decode[ImageContentRequest](envelope.Body)
			if err != nil || request.Query != q {
				return mydcp.ErrFrame
			}
			if err = streamEOF(stream); err != nil {
				return err
			}
			source := ImageContentSource{Info: info, Body: io.NopCloser(bytes.NewReader(payload)), Authorize: func(context.Context) error { return nil }}
			defer source.Body.Close()
			return sendImageContent(ctx, stream, frame, sha256.Sum256(frame.Fields[0].Value), source)
		}()
		completed <- result
		return result
	}); err != nil {
		t.Fatal(err)
	}
	ingressBinding := Service{Mesh: ingress, Self: node, Policy: control.Policy{Cluster: c.Cluster}}
	if err = ingress.OnManagement(mydcp.ImageContent, func(ctx context.Context, conn *mydcp.Session, stream mydcp.Stream, frame mydcp.Frame) error {
		result := func() error {
			envelope, err := schema.Decode[Envelope](frame.Fields[0].Value)
			if err != nil {
				return err
			}
			binding, err := ingressBinding.binding(conn, frame.Kind, envelope)
			if err != nil {
				return err
			}
			request, err := schema.Decode[ImageContentRequest](envelope.Body)
			if err != nil {
				return err
			}
			if err = streamEOF(stream); err != nil {
				return err
			}
			return ingressBinding.forwardImageContent(ctx, stream, frame, sha256.Sum256(frame.Fields[0].Value), envelope, binding, request, owner.Public)
		}()
		completed <- result
		return result
	}); err != nil {
		t.Fatal(err)
	}
	if err = ingress.ListenUnix(filepath.Join(root, "api.sock")); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	var output bytes.Buffer
	got, err := c.ReadImageContent(ctx, ingressPeer, session, "tenant", q, &output)
	if err != nil || got != info || !bytes.Equal(output.Bytes(), payload) {
		t.Fatal("owner relay changed original body", got, err)
	}
	for range 2 {
		select {
		case err := <-completed:
			if err != nil {
				t.Fatal("relay protocol", err)
			}
		case <-ctx.Done():
			t.Fatal("relay not joined", ctx.Err())
		}
	}
}
