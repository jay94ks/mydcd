// SPDX-License-Identifier: Apache-2.0

package server

import (
	"testing"

	"github.com/jay94ks/seafield/internal/ingress"
)

func TestRouteCertificatesOnePerFamily(t *testing.T) {
	a, b := [32]byte{1}, [32]byte{2}
	obs := []ingress.CertificateObservation{
		{Host: "shop.example.com", Fingerprint: a, Family: "ecdsa"},
		{Host: "shop.example.com", Fingerprint: b, Family: "rsa", Error: "certificate-load-failed"},
		{Host: "other.example.com", Error: "missing"},
	}
	got := routeCertificates(obs, "shop.example.com")
	if len(got) != 2 || got[0]["id"] != fpHex(a) || got[0]["alg"] != "ecdsa" || got[1]["alg"] != "rsa" || got[1]["error"] != "certificate-load-failed" {
		t.Fatalf("shop: %v", got)
	}
	if got := routeCertificates(obs, "other.example.com"); len(got) != 1 || got[0]["id"] != nil || got[0]["error"] != "missing" {
		t.Fatalf("missing: %v", got)
	}
	if got := routeCertificates(obs, "none.example.com"); got != nil {
		t.Fatalf("unobserved: %v", got)
	}
}
