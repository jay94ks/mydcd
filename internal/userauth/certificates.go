// SPDX-License-Identifier: Apache-2.0

package userauth

import (
	"time"

	"context"
	"fmt"
	"github.com/jay94ks/seafield/internal/cluster"
	"io"
	"strings"
	"unicode/utf8"

	"github.com/jay94ks/seafield/internal/access"
	"github.com/jay94ks/seafield/internal/certstore"
	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/sfcp"
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
func (c Client) WriteCertificate(ctx context.Context, target sfcp.Peer, session access.Session, q CertificateInput) (certstore.Certificate, error) {
	if !validCertificateInput(q) {
		return certstore.Certificate{}, sfcp.ErrAdmission
	}
	reply, err := c.WriteVault(ctx, target, session, SecretRequest{ID: q.Request, Mode: "certificate", Certificate: &q})
	if err != nil {
		return certstore.Certificate{}, err
	}
	v := reply.Certificate
	if v == nil || v.Validate() != nil || v.Cluster != c.Cluster || v.Request != q.Request || v.Metadata.UploadedBy != session.User {
		return certstore.Certificate{}, sfcp.ErrFrame
	}
	return *v, nil
}
func (c Client) QueryCertificates(ctx context.Context, target sfcp.Peer, session access.Session, q control.CertificateQuery) (control.CertificatePage, error) {
	r, err := call(ctx, c, target, session, CertificatesMethod, q)
	return r.Page, err
}

// CertificatesReply is the reply of the certificates method.
type CertificatesReply struct {
	Page         control.CertificatePage
	RootRevision uint64
}

var CertificatesMethod = define(Method[control.CertificateQuery, CertificatesReply]{Name: "certificates"}, true, func(_ context.Context, s Service, view cluster.View, session access.Session, q control.CertificateQuery) (CertificatesReply, string) {
	if len(q.After) > 512 {
		return CertificatesReply{}, "denied"
	}
	page, err := s.Policy.CertificatePage(view.State, session, time.Now().Unix(), q)
	if err != nil {
		return CertificatesReply{}, "denied"
	}
	return CertificatesReply{Page: page, RootRevision: view.State.Object(control.CertificatesKey).Revision}, "ok"
})
