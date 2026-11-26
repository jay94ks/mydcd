// SPDX-License-Identifier: Apache-2.0

package app

import (
	"crypto/tls"
	"github.com/jay94ks/mydcd/internal/certstore"
	"github.com/jay94ks/mydcd/internal/ingress"
	"testing"
)

func TestIngressCertificateReuseRequiresExactPublicVersionDigest(t *testing.T) {
	v := certstore.Certificate{Metadata: certstore.Metadata{ID: certstore.ID{3}, NotAfter: 12345}}
	previous := ingress.CertificateVersion{Digest: v.Digest(), Fingerprint: v.Metadata.ID, NotAfter: v.Metadata.NotAfter, Certificate: tls.Certificate{PrivateKey: &struct{}{}}}
	reused, ok := reusableIngressCertificate(v, []ingress.CertificateVersion{previous})
	if !ok || reused.Certificate.PrivateKey != previous.Certificate.PrivateKey {
		t.Fatal("unchanged approved source repeated private unwrap")
	}
	changed := v
	changed.Metadata.UploadedBy = "different"
	if _, ok := reusableIngressCertificate(changed, []ingress.CertificateVersion{previous}); ok {
		t.Fatal("ID accepted changed public source digest")
	}
	previous.Digest = [32]byte{}
	if _, ok := reusableIngressCertificate(v, []ingress.CertificateVersion{previous}); ok {
		t.Fatal("legacy unpinned private pair reused")
	}
}
