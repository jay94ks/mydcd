// SPDX-License-Identifier: Apache-2.0

package control

import (
	"bytes"
	"crypto/ed25519"
	"testing"

	"github.com/jay94ks/mydcd/internal/cluster/state"
)

// Real certificate/identity reducers and snapshot bytes, with modeled native
// membership configuration. Material I/O/TLS is in the installed app fixture.
func TestCertificateRotationKeepsOriginalSealerAndRejectsNewOldKeyPublication(t *testing.T) {
	f := newBackupCore(t)
	source := &nodeStorageFixture{p: f.p, node: f.node}
	first := controlCertificate(t, source, 1, "certificate-original")
	f.apply("certificate-original", "put-certificate", 0, CertificatePut{Certificate: first}, state.Applied)
	next := rotateRQ9CoreOwner(t, f)
	current := [32]byte(next.Public().(ed25519.PublicKey))
	catalog, err := f.p.Certificates(f.s)
	if err != nil {
		t.Fatal(err)
	}
	e, ok := catalog.Entry(first.Metadata.ID)
	retained := e.Certificate
	if !ok || retained.Sealer != first.Sealer || retained.Digest() != first.Digest() || !bytes.Equal(retained.SealedKey, first.SealedKey) || !bytes.Equal(retained.Signature, first.Signature) {
		t.Fatal("rotation rewrote original public ciphertext/receipt")
	}
	if f.p.currentResourceKey(f.s, first.Sealer, true) != current {
		t.Fatal("original sealer does not route to current physical owner")
	}
	old := controlCertificate(t, source, 2, "certificate-old-again")
	f.apply("certificate-old-again", "put-certificate", 0, CertificatePut{Certificate: old}, state.Forbidden)
	source.node = next
	updated := controlCertificate(t, source, 2, "certificate-current")
	f.apply("certificate-current", "put-certificate", 0, CertificatePut{Certificate: updated}, state.Applied)
	raw, err := state.Encode(f.s)
	if err != nil {
		t.Fatal(err)
	}
	restored, err := state.Decode(raw)
	if err != nil {
		t.Fatal(err)
	}
	catalog, err = f.p.Certificates(restored)
	if err != nil {
		t.Fatal(err)
	}
	a, okA := catalog.Entry(first.Metadata.ID)
	b, okB := catalog.Entry(updated.Metadata.ID)
	if !okA || !okB || len(catalog.Certificates) != 2 || a.Certificate.Digest() != first.Digest() || b.Certificate.Sealer != current {
		t.Fatal("snapshot lost original certificate history")
	}
}
