// SPDX-License-Identifier: Apache-2.0

package userauth

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/jay94ks/seafield/internal/access"
	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/identity"
	"github.com/jay94ks/seafield/internal/sfcp"
	"github.com/jay94ks/seafield/internal/storage"
	checker "github.com/jay94ks/seafield/internal/workload/lifecycle"
)

// Real Unix TLS/frames, current access core and bbolt source store; the quorum
// permit is simulated here. Runtime's real quorum join is a separate L1 case.
type sourceTestBackend struct {
	mu                                 sync.Mutex
	store                              *checker.SourceStore
	users                              access.Catalog
	policy                             checker.TenantPolicy
	cluster, issuer                    [32]byte
	stages                             int
	loseReply, denyAfterPermit, denied bool
}

func (b *sourceTestBackend) Permit(_ context.Context, s access.Session, d checker.SourceDescriptor, recover bool) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.denied {
		return access.ErrDenied
	}
	issuer := access.Issuer{Key: b.issuer, Epoch: 1, Enabled: true}
	var err error
	if recover {
		err = b.users.AuthorizeSessionCleanup(s, b.cluster, issuer, time.Now().Unix(), d.Tenant, access.ManageServices)
	} else {
		err = b.users.AuthorizeSession(s, b.cluster, issuer, time.Now().Unix(), d.Tenant, access.ManageServices, "node")
		if err == nil && !b.policy.AllowsDescriptor(d) {
			err = access.ErrDenied
		}
	}
	if err == nil && b.denyAfterPermit {
		b.denied = true
	}
	return err
}

func (b *sourceTestBackend) Stage(ctx context.Context, s access.Session, d checker.SourceDescriptor, data []byte) (checker.SourceFact, error) {
	if err := b.Permit(ctx, s, d, false); err != nil {
		return checker.SourceFact{}, err
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	b.stages++
	fact, err := b.store.Stage(ctx, d, data, b.policy)
	if err == nil && b.loseReply {
		b.loseReply = false
		return checker.SourceFact{}, checker.ErrSourceUncertain
	}
	return fact, err
}

func (b *sourceTestBackend) Recover(ctx context.Context, s access.Session, d checker.SourceDescriptor) (checker.SourceFact, error) {
	if err := b.Permit(ctx, s, d, true); err != nil {
		return checker.SourceFact{}, err
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.store.Recover(ctx, d)
}

func sourceStreamFixture(t *testing.T) (Client, sfcp.Peer, access.Session, *sourceTestBackend) {
	t.Helper()
	root, err := os.MkdirTemp("", "sfc-l1-source-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.RemoveAll(root); err != nil {
			t.Error(err)
		}
	})
	node, err := identity.Ephemeral()
	if err != nil {
		t.Fatal(err)
	}
	self, err := identity.Ephemeral()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { clear(node.Private); clear(self.Private) })
	cluster := [32]byte{114}
	peer := sfcp.Peer{ID: "node", Endpoint: "unix://" + filepath.Join(root, "sfcdp.sock"), Policy: sfcp.Policy{Key: sfcp.Identity(node.Public), Respond: true}}
	lookup := func(key sfcp.Identity) (sfcp.Peer, bool) {
		if key == sfcp.Identity(self.Public) {
			return sfcp.Peer{ID: "user", Policy: sfcp.Policy{Key: key, UserAuth: true}}, true
		}
		return peer, key == peer.Key
	}
	server, err := sfcp.NewTransport(node, cluster, lookup)
	if err != nil {
		t.Fatal(err)
	}
	mesh, err := sfcp.NewTransport(self, cluster, lookup)
	if err != nil {
		server.Close()
		t.Fatal(err)
	}
	var db *storage.DB
	var store *checker.SourceStore
	t.Cleanup(func() {
		_ = mesh.Close()
		_ = server.Close()
		if store != nil {
			_ = store.Close()
		}
		if db != nil {
			_ = db.Close()
		}
	})
	db, err = storage.Open(filepath.Join(root, "observations.db"))
	if err != nil {
		t.Fatal(err)
	}
	store, err = checker.OpenSources(db, cluster, node.Private)
	if err != nil {
		t.Fatal(err)
	}
	users, _ := access.New(self.Public)
	users, err = users.Enroll(self.Public, access.User{ID: "operator", Username: "operator", Enabled: true, SystemAdmin: true, Credentials: []access.Credential{{ID: "key", Method: access.PrivateKey, PublicKey: self.Public, Enabled: true}}})
	if err != nil {
		t.Fatal(err)
	}
	users, err = users.CreateTenant("operator", "tenant", 0)
	if err != nil {
		t.Fatal(err)
	}
	tenant, _ := users.Tenant("tenant")
	users, err = users.SetNodes("operator", "tenant", tenant.Revision, []string{"node"})
	if err != nil {
		t.Fatal(err)
	}
	backend := &sourceTestBackend{store: store, users: users, cluster: cluster, issuer: node.Public, policy: checker.TenantPolicy{Tenant: "tenant", Revision: 1, Enabled: true,
		Execution: checker.ExecutionPolicy{MaxConcurrent: 1, TimeoutMS: 1000, NanoCPU: 100_000_000, MemoryBytes: 32 << 20, MaxPIDs: 16, OutputBytes: 4096, ProbeBytes: 4096, Capabilities: []string{"file"}},
		Resolver:  checker.ResolverPolicy{AllowPackages: []string{"context", "github.com/jay94ks/seafield/lifecycle/v1"}, SourceCacheBytes: 1 << 20}}}
	svc := Service{Mesh: server, Self: node, Policy: control.Policy{Cluster: cluster}, CheckerSources: backend}
	if err := server.OnManagement(sfcp.User, func(ctx context.Context, conn *sfcp.Session, stream sfcp.Stream, frame sfcp.Frame) error {
		// This fixture verifies the source protocol/store with a modeled current
		// authority. Actual managed node/Engine admission is covered by runtime tests.
		if len(frame.Fields) != 2 {
			return sfcp.ErrFrame
		}
		digest := sha256.Sum256(frame.Fields[0].Value)
		var envelope Envelope
		var request Request
		if !bytes.Equal(digest[:], frame.Fields[1].Value) || strict(frame.Fields[0].Value, &envelope) != nil || strict(envelope.Body, &request) != nil || request.Schema != 1 || request.Nonce == ([32]byte{}) {
			return sfcp.ErrFrame
		}
		binding, err := svc.binding(conn, frame.Kind, envelope)
		if err != nil {
			return err
		}
		return svc.streamCheckerSource(ctx, conn, stream, frame, digest, envelope, request, binding)
	}); err != nil {
		t.Fatal(err)
	}
	if err := server.ListenUnix(filepath.Join(root, "sfcdp.sock")); err != nil {
		t.Fatal(err)
	}
	u, _ := users.User("operator")
	now := time.Now().Unix()
	session := access.Session{Schema: 1, ID: "source-session", Cluster: cluster, User: u.ID, Credential: "key", AccountRevision: u.Revision, Key: self.Public, Issuer: node.Public, IssuerEpoch: 1, IssuedAt: now, ExpiresAt: now + 3600, Scopes: []access.Scope{{Tenant: "tenant", Actions: []access.Action{access.ManageServices}}}}
	session.Signature = ed25519.Sign(node.Private, access.SessionBytes(session))
	c := Client{Mesh: mesh, Self: self, Cluster: cluster, Peers: []sfcp.Peer{peer}}
	// Every transfer carries its original upload ID; this is the fixture's.
	c = withUpload(c, "fixture upload")
	return c, peer, session, backend
}

// withUpload is c with the original upload ID of a distinct CLI intent.
func withUpload(c Client, label string) Client {
	return c.WithCheckerUpload(CheckerScriptIntent{Signature: ed25519.Sign(c.Self.Private, []byte(label))})
}

func streamedSource(data []byte) checker.SourceDescriptor {
	return checker.SourceDescriptor{Tenant: "tenant", Digest: sha256.Sum256(data), Length: uint64(len(data)), SDK: 1}
}

func TestCheckerActualUnixSourceChunksLostResultRecoveryAndRevocation(t *testing.T) {
	c, peer, session, backend := sourceStreamFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	data := append([]byte("package checker\n"), bytes.Repeat([]byte("// source chunk\n"), 4000)...)
	d := streamedSource(data)
	fact, err := c.StageCheckerSource(ctx, peer, session, d, data)
	if err != nil || fact.Verify() != nil {
		t.Fatal("actual Unix TLS/chunks/source DB", err)
	}
	actual, err := backend.store.Read(ctx, d)
	if err != nil || !bytes.Equal(actual, data) {
		t.Fatal("stored bytes differ from signed transfer", err)
	}
	data = []byte("package checker\n// uncertain response\n")
	d = streamedSource(data)
	c = withUpload(c, "uncertain response") // one original upload per source
	backend.mu.Lock()
	backend.loseReply = true
	backend.mu.Unlock()
	if _, err := c.StageCheckerSource(ctx, peer, session, d, data); err == nil {
		t.Fatal("injected lost result became success")
	} else {
		var outcome *Error
		if !errors.As(err, &outcome) || outcome.Phase != sfcp.Unknown {
			t.Fatal("lost result not retained as unknown", err)
		}
	}
	recovered, err := c.RecoverCheckerSource(ctx, peer, session, d)
	if err != nil || recovered.ContentDigest() != d.ContentDigest() {
		t.Fatal("explicit recover did not retrieve original", err)
	}
	backend.mu.Lock()
	count := backend.stages
	backend.policy.Enabled = false
	backend.mu.Unlock()
	if count != 2 {
		t.Fatal("source recovery automatically resubmitted bytes", count)
	}
	if _, err := c.RecoverCheckerSource(ctx, peer, session, d); err != nil {
		t.Fatal("policy revocation erased original fact", err)
	}
	if _, err := c.StageCheckerSource(ctx, peer, session, d, data); err == nil {
		t.Fatal("revoked policy admitted new stage")
	}
}

func TestCheckerActualSourcePermissionRecheckedAfterInput(t *testing.T) {
	c, peer, session, backend := sourceStreamFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
	defer cancel()
	data := []byte("package checker\n")
	d := streamedSource(data)
	backend.mu.Lock()
	backend.denyAfterPermit = true
	backend.mu.Unlock()
	if _, err := c.StageCheckerSource(ctx, peer, session, d, data); err == nil {
		t.Fatal("preflight grant survived revocation before store")
	}
	if _, err := backend.store.Read(ctx, d); err == nil {
		t.Fatal("denied source was persisted")
	}
	backend.mu.Lock()
	stages := backend.stages
	backend.mu.Unlock()
	if stages != 0 {
		t.Fatal("revoked source reached storage")
	}
}

func TestCheckerActualSourceRejectsWrongOffsetHeaderAndTrailingBytes(t *testing.T) {
	c, peer, session, backend := sourceStreamFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	for _, mode := range []string{"offset", "header", "trailing"} {
		t.Run(mode, func(t *testing.T) {
			data := []byte("package checker\n// " + mode + "\n")
			d := streamedSource(data)
			conn, err := c.Mesh.Dial(ctx, peer)
			if err != nil {
				t.Fatal(err)
			}
			stream, err := conn.OpenManagement(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer stream.CancelRead(0)
			defer stream.Close()
			body, _ := requestBody(Request{CheckerUpload: withUpload(c, mode).checkerUpload, Method: "checker-source-stage", Tenant: "tenant", CheckerSource: &d})
			envelope := Envelope{Body: body, Session: &session, Signature: ed25519.Sign(c.Self.Private, access.RequestBytes(session, conn.PeerChallenge(), body))}
			raw, _ := json.Marshal(envelope)
			header := sha256.Sum256(raw)
			id := c.Mesh.NextRequest()
			if err := sfcp.WriteFrame(stream, sfcp.Frame{Purpose: sfcp.User, Kind: 1, Request: id, Fields: []sfcp.Field{{Tag: 1, Required: true, Value: raw}, {Tag: 2, Required: true, Value: header[:]}}}); err != nil {
				t.Fatal(err)
			}
			ready, err := sfcp.ReadFrame(stream, 128<<10)
			var reply Reply
			if err != nil || strict(ready.Fields[0].Value, &reply) != nil || reply.Code != "continue" {
				t.Fatal("source preflight", err)
			}
			var offset [8]byte
			if mode == "offset" {
				binary.LittleEndian.PutUint64(offset[:], 1)
			}
			if mode == "header" {
				header[0] ^= 1
			}
			if err := sfcp.WriteFrame(stream, sfcp.Frame{Purpose: sfcp.User, Kind: 4, Request: id, Fields: []sfcp.Field{{Tag: 1, Required: true, Value: offset[:]}, {Tag: 2, Required: true, Value: data}, {Tag: 3, Required: true, Value: header[:]}}}); err != nil {
				t.Fatal(err)
			}
			if mode == "trailing" {
				_, _ = stream.Write([]byte{1})
			}
			_ = stream.Close()
			if _, err := sfcp.ReadFrame(stream, 128<<10); err == nil {
				t.Fatal("malformed content returned a success frame")
			}
			if _, err := backend.store.Read(ctx, d); err == nil {
				t.Fatal("malformed stream published source")
			}
		})
	}
	backend.mu.Lock()
	stages := backend.stages
	backend.mu.Unlock()
	if stages != 0 {
		t.Fatal("incomplete/bad stream reached artifact store", stages)
	}
}
