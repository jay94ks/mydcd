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
	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/sfcp"
	"github.com/jay94ks/seafield/internal/vps"
)

// VPSCredentialInput is a provider key pair to seal for Account; a vendor
// with one bearer token (vps.Vendor.TokenOnly) sends it as AccessKey and no
// SecretKey. Like
// CertificateInput it travels only on the sensitive input purpose and never
// enters a Request, a UserOperation or a journal. Request is the write ID of
// the put-vps-account the sealed result will go into.
type VPSCredentialInput struct {
	Request, Account     string
	AccessKey, SecretKey []byte `json:",omitempty"`
}

func (VPSCredentialInput) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "[redacted vps credential input]")
}

func validVPSCredentialInput(q VPSCredentialInput) bool {
	return q.Request != "" && len(q.Request) <= 128 && utf8.ValidString(q.Request) && !strings.ContainsAny(q.Request, "\x00\r\n") &&
		vps.ValidAccountName(q.Account) && len(q.AccessKey) > 0 && len(q.AccessKey) <= 256 && len(q.SecretKey) <= 256
}

// SealVPSCredential asks the target, which must be a current voter, to seal
// a provider key pair. Sealing changes no state: after a lost reply the
// caller simply asks again.
func (c Client) SealVPSCredential(ctx context.Context, target sfcp.Peer, session access.Session, q VPSCredentialInput) (vps.SealedCredential, error) {
	if !validVPSCredentialInput(q) {
		return vps.SealedCredential{}, sfcp.ErrAdmission
	}
	reply, err := c.WriteVault(ctx, target, session, SecretRequest{ID: q.Request, Mode: "vps-credential", VPSCredential: &q})
	if err != nil {
		return vps.SealedCredential{}, err
	}
	v := reply.VPSCredential
	if v == nil || v.Validate() != nil || v.Cluster != c.Cluster || v.Account != q.Account || v.Request != q.Request {
		return vps.SealedCredential{}, sfcp.ErrFrame
	}
	return *v, nil
}

// QueryVPS reads the VPS provider accounts (system administrators).
func (c Client) QueryVPS(ctx context.Context, target sfcp.Peer, session access.Session, q control.VPSQuery) (control.VPSPage, error) {
	r, err := call(ctx, c, target, session, VPSMethod, q)
	return r.Page, err
}

// QueryVPSOffer asks the target, which must be a current voter, to read
// what an account's vendor sells now. It changes nothing.
func (c Client) QueryVPSOffer(ctx context.Context, target sfcp.Peer, session access.Session, q control.VPSOfferQuery) (control.VPSOffer, error) {
	if !q.Valid() {
		return control.VPSOffer{}, sfcp.ErrAdmission
	}
	r, err := call(ctx, c, target, session, VPSMethod, control.VPSQuery{Offer: &q})
	if err != nil {
		return control.VPSOffer{}, err
	}
	if r.Offer == nil || r.Offer.Account != q.Account {
		return control.VPSOffer{}, sfcp.ErrFrame
	}
	return *r.Offer, nil
}

// QueryVPSStatus reads the leader's live cost watch through target.
func (c Client) QueryVPSStatus(ctx context.Context, target sfcp.Peer, session access.Session) (VPSReply, error) {
	r, err := call(ctx, c, target, session, VPSMethod, control.VPSQuery{Status: true})
	if err != nil {
		return VPSReply{}, err
	}
	if r.Status == nil {
		return VPSReply{}, sfcp.ErrFrame
	}
	return r, nil
}

// VPSReply is the reply of the vps method. Offer is set only when the query
// asked for one.
type VPSReply struct {
	Page         control.VPSPage
	RootRevision uint64
	Offer        *control.VPSOffer  `json:",omitempty"`
	Status       *control.VPSStatus `json:",omitempty"`
}

var VPSMethod = define(Method[control.VPSQuery, VPSReply]{Name: "vps"}, true, func(ctx context.Context, s Service, view cluster.View, session access.Session, q control.VPSQuery) (VPSReply, string) {
	page, err := s.Policy.VPSPage(view.State, session, time.Now().Unix(), q)
	if err != nil {
		return VPSReply{}, "denied"
	}
	reply := VPSReply{Page: page, RootRevision: view.State.Object(control.VPSKey).Revision}
	if q.Offer != nil {
		if s.VPSOfferReader == nil {
			return VPSReply{}, "unavailable"
		}
		offer, err := s.VPSOfferReader(ctx, session, *q.Offer)
		if err != nil {
			return VPSReply{}, "unavailable"
		}
		reply.Offer = &offer
	}
	if q.Status {
		if s.VPSStatusReader == nil {
			return VPSReply{}, "unavailable"
		}
		status, err := s.VPSStatusReader(ctx)
		if err != nil {
			return VPSReply{}, "unavailable"
		}
		reply.Status = &status
	}
	return reply, "ok"
})
