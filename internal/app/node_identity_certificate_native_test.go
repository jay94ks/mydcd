// SPDX-License-Identifier: Apache-2.0

package app

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jay94ks/seafield/internal/access"
	"github.com/jay94ks/seafield/internal/certstore"
	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/schema"
	"github.com/jay94ks/seafield/internal/sfcp"
	"github.com/jay94ks/seafield/internal/storage"
	"github.com/jay94ks/seafield/internal/userauth"

	bolt "go.etcd.io/bbolt"
)

// This extends the existing native fixture and its owned ingress rollback.
// No additional daemon/node or native certificate proof is manufactured.
func prepareIdentityCertificate(t *testing.T, ctx context.Context, r *Runtime, user userauth.Client, peer sfcp.Peer, session access.Session, change func(string, string, uint64, any)) {
	t.Helper()
	registerTestDomain(t, ctx, user, peer, session, change, "app.test")
	material, _ := rq7Certificate(t, "app.test")
	defer material.Clear()
	v, err := user.WriteCertificate(ctx, peer, session, userauth.CertificateInput{Request: "identity-server-request", Chain: material.Chain, Key: material.Key})
	if err != nil {
		t.Fatal("original certificate input", err)
	}
	change("identity-server-request", "put-certificate", 0, control.CertificatePut{Certificate: v})
	other, _ := rq7Certificate(t, "app.test")
	defer other.Clear()
	pending, err := user.WriteCertificate(ctx, peer, session, userauth.CertificateInput{Request: "identity-pending-request", Chain: other.Chain, Key: other.Key})
	if err != nil || pending.Sealer != r.Identity.Public {
		t.Fatal("original pending certificate receipt", err)
	}
}

// prepareIngressCertificate stores the certificate the managed ingress
// fixture serves for app.test; TLS listeners choose it by host.
func prepareIngressCertificate(t *testing.T, ctx context.Context, user userauth.Client, peer sfcp.Peer, session access.Session, change func(string, string, uint64, any)) {
	t.Helper()
	registerTestDomain(t, ctx, user, peer, session, change, "app.test")
	material, _ := rq7Certificate(t, "app.test")
	defer material.Clear()
	v, err := user.WriteCertificate(ctx, peer, session, userauth.CertificateInput{Request: "app-test-request", Chain: material.Chain, Key: material.Key})
	if err != nil {
		t.Fatal("ingress certificate input", err)
	}
	change("app-test-request", "put-certificate", 0, control.CertificatePut{Certificate: v})
}

// registerTestDomain adds a cluster domain once, so stored certificates
// under it get links.
func registerTestDomain(t *testing.T, ctx context.Context, user userauth.Client, peer sfcp.Peer, session access.Session, change func(string, string, uint64, any), name string) {
	t.Helper()
	page, err := user.QueryCertificates(ctx, peer, session, control.CertificateQuery{})
	if err != nil {
		t.Fatal("read domain list", err)
	}
	for _, d := range page.Domains {
		if d.Name == name {
			return
		}
	}
	change("domain-"+name, "add-domain", page.Revision, control.DomainChange{Name: name})
}

// storedByRequest finds the stored certificate an original request put.
func storedByRequest(t *testing.T, catalog certstore.Catalog, request string) certstore.Certificate {
	t.Helper()
	for _, e := range catalog.Certificates {
		if e.Certificate.Request == request {
			return e.Certificate
		}
	}
	t.Fatal("stored certificate missing", request)
	return certstore.Certificate{}
}

// storeFileCertificate puts a fixture's PEM files into the store.
func storeFileCertificate(t *testing.T, ctx context.Context, user userauth.Client, peer sfcp.Peer, session access.Session, change func(string, string, uint64, any), chainFile, keyFile string) {
	t.Helper()
	chain, err := os.ReadFile(chainFile)
	if err != nil {
		t.Fatal(err)
	}
	key, err := os.ReadFile(keyFile)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(key)
	in, err := certstore.Inspect(chain, time.Now().Unix())
	if err != nil {
		t.Fatal(err)
	}
	for _, host := range in.Metadata.Hosts {
		if d, ok := certstore.NormalizeDomain(strings.TrimPrefix(host, "*.")); ok {
			registerTestDomain(t, ctx, user, peer, session, change, d)
		}
	}
	v, err := user.WriteCertificate(ctx, peer, session, userauth.CertificateInput{Request: "fixture-certificate", Chain: chain, Key: key})
	if err != nil {
		t.Fatal("fixture certificate input", err)
	}
	change("fixture-certificate", "put-certificate", 0, control.CertificatePut{Certificate: v})
}

func certificateNativeRecords(t *testing.T, r *Runtime) map[string][]byte {
	t.Helper()
	records := map[string][]byte{}
	if err := r.reports.View(func(tx *bolt.Tx) error {
		bucket := tx.Bucket([]byte("certificate-native-2"))
		if bucket == nil {
			return storage.ErrMissing
		}
		return bucket.ForEach(func(k, v []byte) error { records[string(k)] = bytes.Clone(v); return nil })
	}); err != nil {
		t.Fatal("read original certificate namespace", err)
	}
	return records
}

func captureIdentityCertificate(t *testing.T, ctx context.Context, runtime **Runtime, user *userauth.Client, peer *sfcp.Peer, session *access.Session, policy control.Policy) func() {
	t.Helper()
	original := *runtime
	view, err := original.currentView(ctx)
	if err != nil {
		t.Fatal(err)
	}
	catalog, err := policy.Certificates(view.State)
	if err != nil {
		t.Fatal(err)
	}
	version := storedByRequest(t, catalog, "identity-server-request")
	pending, err := original.certificateNative().Recover(session.User, "identity-pending-request")
	if err != nil {
		t.Fatal(err)
	}
	records := certificateNativeRecords(t, original)
	old := original.Identity.Public
	return func() {
		t.Helper()
		current := *runtime
		retained, ok := current.nativeOwner(old)
		if !ok {
			t.Fatal("original certificate namespace lost")
		}
		currentView, err := current.currentView(ctx)
		if err != nil {
			t.Fatal(err)
		}
		key, err := current.voterKey(currentView.State, version.Metadata.ID)
		if err != nil {
			t.Fatal("current runtime cannot open original envelope", err)
		}
		if _, err = certstore.Open(version, key); err != nil {
			clear(key)
			t.Fatal(err)
		}
		clear(key)
		recovered, err := user.WriteCertificate(ctx, *peer, *session, userauth.CertificateInput{Request: "identity-pending-request", Recover: true})
		if err != nil || recovered.Digest() != pending.Digest() || recovered.Sealer != old || !bytes.Equal(recovered.SealedKey, pending.SealedKey) || !bytes.Equal(recovered.Signature, pending.Signature) {
			t.Fatal("current TLS recovery replaced original certificate receipt", err)
		}
		if _, err = user.WriteCertificate(ctx, *peer, *session, userauth.CertificateInput{Request: "not-original", Recover: true}); err == nil {
			t.Fatal("missing recovery created certificate")
		}
		replacement, _ := rq7Certificate(t, "app.test")
		_, replayErr := user.WriteCertificate(ctx, *peer, *session, userauth.CertificateInput{Request: "identity-pending-request", Chain: replacement.Chain, Key: replacement.Key})
		replacement.Clear()
		if replayErr == nil {
			t.Fatal("original certificate request allocated again under current identity")
		}
		// The retained Source/Consumer identifies the original ingress. The wire
		// authenticates the current key and the common quorum view rechecks it.
		q, err := retained.certificateRead(ctx, version, "app.test")
		if err != nil || q.Consumer != old {
			t.Fatal("original ingress source not retained", err)
		}
		target, ok := current.resourcePeerForKey(ctx, version.Sealer)
		if !ok || [32]byte(target.Key) != current.Identity.Public {
			t.Fatal("original sealer did not resolve to current peer")
		}
		client, err := sfcp.NewTransport(current.Identity, policy.Cluster, func(key sfcp.Identity) (sfcp.Peer, bool) { return current.Mesh.Peer(key) })
		if err != nil {
			t.Fatal(err)
		}
		defer client.Close()
		conn, err := client.Dial(ctx, target)
		if err != nil {
			t.Fatal("current actual TLS material connection", err)
		}
		raw, _ := json.Marshal(certificateRequest{Read: &q})
		body, err := conn.FetchCertificateMaterial(ctx, raw)
		if err != nil {
			t.Fatal("current TLS fetch of original certificate", err)
		}
		reply, decodeErr := schema.Decode[certificateKeyReply](body)
		clear(body)
		if decodeErr != nil || reply.Schema != 1 || reply.Certificate != version.Digest() {
			clear(reply.Key)
			t.Fatal("material changed original digest", decodeErr)
		}
		_, openErr := certstore.Open(version, reply.Key)
		clear(reply.Key)
		if openErr != nil {
			t.Fatal("current wire cannot unwrap original version", openErr)
		}
		for _, mutate := range []func(*control.CertificateMaterialRead){func(q *control.CertificateMaterialRead) { q.Source.Revision++ }, func(q *control.CertificateMaterialRead) { q.Certificate[0] ^= 1 }, func(q *control.CertificateMaterialRead) { q.Consumer[0] ^= 1 }} {
			bad := q
			mutate(&bad)
			raw, _ = json.Marshal(certificateRequest{Read: &bad})
			body, err = conn.FetchCertificateMaterial(ctx, raw)
			clear(body)
			if err == nil {
				t.Fatal("changed original certificate/source accepted")
			}
		}
		oldClient, err := sfcp.NewTransport(retained.Identity, policy.Cluster, func(key sfcp.Identity) (sfcp.Peer, bool) { return current.Mesh.Peer(key) })
		if err != nil {
			t.Fatal(err)
		}
		defer oldClient.Close()
		attempt, stop := context.WithTimeout(ctx, 5*time.Second)
		_, err = oldClient.Dial(attempt, target)
		stop()
		if err == nil {
			t.Fatal("retired certificate sealer authenticated current transport")
		}
		after := certificateNativeRecords(t, retained)
		if len(after) != len(records) {
			t.Fatal("original namespace allocated/replaced certificate records")
		}
		for k, raw := range records {
			if !bytes.Equal(raw, after[k]) {
				t.Fatal("identity rotation rewrote original certificate ciphertext/receipt")
			}
		}
	}
}
