// SPDX-License-Identifier: Apache-2.0

package app

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/jay94ks/seafield/internal/certstore"
	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/cluster/membership"
	"github.com/jay94ks/seafield/internal/identity"
	"github.com/jay94ks/seafield/internal/storage"
	"github.com/jay94ks/seafield/internal/userauth"
)

// The master key starts on the init voter, reaches a promoted voter, and
// leaves a demoted one. A member that is not a voter still seals an
// upload: a voter gives it the derived key after a proof of key
// possession, and both derive the same key.
func TestCertificateMasterFollowsVotersAndSealsOnNonVoter(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	admin, err := identity.Ephemeral()
	if err != nil {
		t.Fatal(err)
	}
	m := newManagedVoters(t, ctx, t.TempDir(), admin, 2)
	first, second := m.Nodes[0], m.Nodes[1]
	master, err := first.certificateMaster()
	if err != nil {
		t.Fatal("init voter has no master key", err)
	}
	defer clear(master)
	m.wait("master on promoted voter", func() bool {
		got, err := second.certificateMaster()
		defer clear(got)
		return err == nil && bytes.Equal(got, master)
	})

	e, _ := m.directory(first).Entry("node-1")
	m.Change(0, "demote-node-1", "demote-node", e.Revision, control.NodeSelection{ID: "node-1"})
	m.wait("node-1 demoted", func() bool {
		e, ok := m.directory(first).Entry("node-1")
		return ok && e.Phase == membership.Ready && !e.Peer.Voter && e.Job.Pending == nil
	})
	m.wait("master erased on demoted node", func() bool {
		_, err := second.certificateMaster()
		return errors.Is(err, storage.ErrMissing)
	})

	material, _ := rq7Certificate(t, "app.test")
	defer material.Clear()
	v, err := m.client.WriteCertificate(ctx, m.Peer(1), m.session, userauth.CertificateInput{Request: "non-voter-upload", Chain: material.Chain, Key: material.Key})
	if err != nil {
		t.Fatal("non-voter upload", err)
	}
	if v.Sealer != second.Identity.Public {
		t.Fatal("upload not sealed by the non-voter input node")
	}
	key, err := certstore.Derive(master, v.Metadata.ID)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(key)
	if _, err = certstore.Open(v, key); err != nil {
		t.Fatal("voter-derived key does not open the non-voter's receipt", err)
	}
}

// Typed methods (R09) go through the same session, relay and leader path:
// both voters answer.
func TestTypedCertificateAndVPSQueriesOnEveryVoter(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	admin, err := identity.Ephemeral()
	if err != nil {
		t.Fatal(err)
	}
	m := newManagedVoters(t, ctx, t.TempDir(), admin, 2)
	for i := range m.Nodes {
		if _, err := m.client.QueryCertificates(ctx, m.Peer(i), m.session, control.CertificateQuery{}); err != nil {
			t.Fatal("typed certificates query", i, err)
		}
		if _, err = m.client.QueryVPS(ctx, m.Peer(i), m.session, control.VPSQuery{}); err != nil {
			t.Fatal("typed vps query", i, err)
		}
		// A malformed selector is refused before it is sent.
		if _, err = m.client.QueryCertificates(ctx, m.Peer(i), m.session, control.CertificateQuery{After: strings.Repeat("x", 600)}); err == nil {
			t.Fatal("oversized cursor accepted", i)
		}
	}
}
