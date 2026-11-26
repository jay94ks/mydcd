// SPDX-License-Identifier: Apache-2.0

package userauth

import (
	"context"
	"fmt"
	"io"
	"strings"
	"unicode/utf8"

	"github.com/jay94ks/mydcd/internal/access"
	"github.com/jay94ks/mydcd/internal/certstore"
	"github.com/jay94ks/mydcd/internal/cluster/control"
	"github.com/jay94ks/mydcd/internal/mydcp"
)

// CertificateInput is explicitly encoded only by purpose10. It never enters
// Request, a UserOperation, public receipts or local CLI operation journals.
// Request is the original write ID; Recover asks for the receipt of an
// earlier dispatch of the same Request without sending material again.
type CertificateInput struct {
	Request    string
	Recover    bool
	Chain, Key []byte `json:",omitempty"`
}

func (q CertificateInput) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "[redacted certificate input]")
}
func validCertificateInput(q CertificateInput) bool {
	return q.Request != "" && len(q.Request) <= 128 && utf8.ValidString(q.Request) && !strings.ContainsAny(q.Request, "\x00\r\n") && (q.Recover && q.Chain == nil && q.Key == nil || !q.Recover && len(q.Chain) > 0 && len(q.Chain) <= certstore.MaxChainBytes && len(q.Key) > 0 && len(q.Key) <= certstore.MaxKeyBytes)
}
func (c Client) WriteCertificate(ctx context.Context, target mydcp.Peer, session access.Session, q CertificateInput) (certstore.Certificate, error) {
	if !validCertificateInput(q) {
		return certstore.Certificate{}, mydcp.ErrAdmission
	}
	reply, err := c.WriteVault(ctx, target, session, SecretRequest{ID: q.Request, Mode: "certificate", Certificate: &q})
	if err != nil {
		return certstore.Certificate{}, err
	}
	v := reply.Certificate
	if v == nil || v.Validate() != nil || v.Cluster != c.Cluster || v.Request != q.Request || v.Metadata.UploadedBy != session.User {
		return certstore.Certificate{}, mydcp.ErrFrame
	}
	return *v, nil
}
func (c Client) QueryCertificates(ctx context.Context, target mydcp.Peer, session access.Session, q control.CertificateQuery) (control.CertificatePage, error) {
	if !q.Valid() {
		return control.CertificatePage{}, mydcp.ErrAdmission
	}
	reply, err := c.query(ctx, target, session, Request{Method: "certificates", Certificate: &q})
	if err != nil {
		return control.CertificatePage{}, err
	}
	if reply.CertificatePage == nil {
		return control.CertificatePage{}, mydcp.ErrFrame
	}
	return *reply.CertificatePage, nil
}
