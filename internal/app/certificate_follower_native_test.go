// SPDX-License-Identifier: Apache-2.0

package app

import (
	"bytes"
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/jay94ks/seafield/internal/access"
	"github.com/jay94ks/seafield/internal/certstore"
	"github.com/jay94ks/seafield/internal/cluster"
	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/schema"
	"github.com/jay94ks/seafield/internal/sfcp"
	"github.com/jay94ks/seafield/internal/userauth"
)

// Reuses the existing joined node-b and the original user session. Only a
// requester transport is added; no issuer, owner, DB or native app moves.
func rq7FollowerCertificateClient(t *testing.T, ctx context.Context, a, b *Runtime, original userauth.Client, source sfcp.Peer, p control.Policy) (userauth.Client, sfcp.Peer) {
	t.Helper()
	if b.Engine().IsLeader() {
		t.Fatal("second native owner unexpectedly became leader")
	}
	view, err := b.currentView(ctx)
	if err != nil || view.Local {
		t.Fatal("non-voter did not consume a current quorum prefix", err)
	}
	members, err := p.Members(view.State)
	if err != nil {
		t.Fatal(err)
	}
	nonvoter := false
	for _, member := range members.Entries {
		if member.Peer.ID == "node-b" && member.Peer.Key == b.Identity.Actor() {
			nonvoter = !member.Peer.Voter
		}
	}
	provider, ok := a.Mesh.Peer(sfcp.Identity(b.Identity.Public))
	if !nonvoter || !ok || !provider.Member || !provider.Respond || !members.WorkKey(b.Identity.Public) {
		t.Fatal("existing second native provider is not the installed non-voter")
	}
	mesh, err := sfcp.NewTransport(original.Self, original.Cluster, func(key sfcp.Identity) (sfcp.Peer, bool) {
		if key == source.Key {
			return source, true
		}
		return provider, key == provider.Key
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = mesh.Close() })
	client := original
	client.Mesh, client.Peers = mesh, []sfcp.Peer{source, provider}
	return client, provider
}

func rq7PrepareFollowerCertificate(t *testing.T, ctx context.Context, a, b *Runtime, user userauth.Client, provider sfcp.Peer, session access.Session, request string, material certstore.Material) certstore.Certificate {
	t.Helper()
	v, err := user.WriteCertificate(ctx, provider, session, userauth.CertificateInput{Request: request, Chain: material.Chain, Key: material.Key})
	if err != nil || v.Sealer != b.Identity.Public {
		t.Fatal("protected input left its original non-voter provider", err)
	}
	again, err := user.WriteCertificate(ctx, provider, session, userauth.CertificateInput{Request: request, Recover: true})
	if err != nil || again.Digest() != v.Digest() || !bytes.Equal(again.Signature, v.Signature) {
		t.Fatal("non-voter recovery changed original provider receipt", err)
	}
	if _, err := a.certificateNative().Recover(session.User, request); err == nil {
		t.Fatal("protected input was also initialized on the leader")
	}
	return v
}

// The first internal certificate is sealed on node-b and consumed by node-a's
// actual TLS gateway. Check the same member material handler's original source
// fence, including malformed/stale selectors, while node-b remains nonleader.
func rq7FollowerCertificateMaterialBoundary(t *testing.T, ctx context.Context, a, b *Runtime, p control.Policy, read func() cluster.View) {
	t.Helper()
	if b.Engine().IsLeader() {
		t.Fatal("certificate provider moved to consensus leader")
	}
	catalog, err := p.Certificates(read().State)
	if err != nil {
		t.Fatal(err)
	}
	v := storedByRequest(t, catalog, "rq7-cert-internal")
	if v.Sealer != b.Identity.Public {
		t.Fatal("original non-voter certificate missing")
	}
	q, err := a.certificateRead(ctx, v, "metrics.example")
	if err != nil || q.Consumer != a.Identity.Public || q.Source.Key == "" {
		t.Fatal("original installed consumer selection missing", err)
	}
	// Only voters answer: node-b sealed the upload but holds no master key.
	follower, ok := a.Mesh.Peer(sfcp.Identity(b.Identity.Public))
	if !ok {
		t.Fatal("follower is not pinned")
	}
	followerConn, err := a.Mesh.Dial(ctx, follower)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(certificateRequest{Read: &q})
	if body, err := followerConn.FetchCertificateMaterial(ctx, raw); err == nil {
		clear(body)
		t.Fatal("non-voter answered a certificate key read")
	}
	// The consumer's own identity asks the voter (node-a) over real TLS.
	voter, ok := a.Mesh.Peer(sfcp.Identity(a.Identity.Public))
	if !ok {
		t.Fatal("voter is not pinned")
	}
	client, err := sfcp.NewTransport(a.Identity, p.Cluster, func(key sfcp.Identity) (sfcp.Peer, bool) { return a.Mesh.Peer(key) })
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	conn, err := client.Dial(ctx, voter)
	if err != nil {
		t.Fatal(err)
	}
	body, err := conn.FetchCertificateMaterial(ctx, raw)
	if err != nil {
		t.Fatal("voter rejected current exact source", err)
	}
	reply, err := schema.Decode[certificateKeyReply](body)
	clear(body)
	defer clear(reply.Key)
	if err != nil || reply.Schema != 1 || reply.Certificate != v.Digest() || len(reply.Key) != 32 {
		t.Fatal("voter reply changed original certificate", err)
	}
	if _, err := certstore.Open(v, reply.Key); err != nil {
		t.Fatal("material fetched from the voter cannot open original certificate", err)
	}
	for _, mode := range []string{"source-revision", "source-generation", "source-key", "consumer", "certificate", "host", "expired-request"} {
		bad := q
		switch mode {
		case "source-revision":
			bad.Source.Revision++
		case "source-generation":
			bad.Source.Generation++
		case "source-key":
			bad.Source.Key += "/different"
		case "consumer":
			bad.Consumer = b.Identity.Public
		case "certificate":
			bad.Certificate[0] ^= 1
		case "host":
			bad.Host = "shop.example"
		case "expired-request":
			bad.At = time.Now().Add(-61 * time.Second).Unix()
		}
		raw, _ := json.Marshal(certificateRequest{Read: &bad})
		body, err := conn.FetchCertificateMaterial(ctx, raw)
		clear(body)
		if err == nil {
			t.Fatal("voter material handler admitted changed original selection", mode)
		}
	}
}
