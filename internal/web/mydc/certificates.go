// SPDX-License-Identifier: Apache-2.0

package mydc

// Certificate store actions (docs/reference/certificate-store.md).
// put-certificate takes control.CertificatePut; delete-certificate and
// disable-certificate take control.CertificateSelection{ID}. Expected is 0:
// the store is keyed by certificate ID. See fake_certificates_real.go.
const (
	ActionPutCertificate     = "put-certificate"
	ActionDeleteCertificate  = "delete-certificate"
	ActionDisableCertificate = "disable-certificate"
	// ActionSetACMEResponder takes control.ACMEResponderChange; Expected is
	// the store revision.
	ActionSetACMEResponder = "set-acme-responder"
)
