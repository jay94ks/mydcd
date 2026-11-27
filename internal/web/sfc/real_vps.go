// SPDX-License-Identifier: Apache-2.0

package sfc

import (
	"context"

	"github.com/jay94ks/seafield/internal/access"
	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/userauth"
	"github.com/jay94ks/seafield/internal/vps"
)

func (c *realConn) QueryVPS(ctx context.Context) (control.VPSPage, error) {
	return realCall(ctx, c, "vps", func(u userauth.Client, s access.Session) (control.VPSPage, error) {
		return u.QueryVPS(ctx, c.peer, s, control.VPSQuery{})
	})
}

func (c *realConn) QueryVPSStatus(ctx context.Context) (control.VPSStatus, error) {
	return realCall(ctx, c, "vps", func(u userauth.Client, s access.Session) (control.VPSStatus, error) {
		r, err := u.QueryVPSStatus(ctx, c.peer, s)
		if err != nil {
			return control.VPSStatus{}, err
		}
		return *r.Status, nil
	})
}

func (c *realConn) QueryVPSOffer(ctx context.Context, q control.VPSOfferQuery) (control.VPSOffer, error) {
	return realCall(ctx, c, "vps", func(u userauth.Client, s access.Session) (control.VPSOffer, error) {
		return u.QueryVPSOffer(ctx, c.peer, s, q)
	})
}

func (c *realConn) SealVPSCredential(ctx context.Context, in userauth.VPSCredentialInput) (vps.SealedCredential, error) {
	return realCall(ctx, c, "vps-credential", func(u userauth.Client, s access.Session) (vps.SealedCredential, error) {
		return u.SealVPSCredential(ctx, c.peer, s, in)
	})
}
