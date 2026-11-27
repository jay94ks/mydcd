// SPDX-License-Identifier: Apache-2.0

package app

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"time"

	"github.com/jay94ks/seafield/internal/access"
	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/sfcp"
	"github.com/jay94ks/seafield/internal/userauth"
	"github.com/jay94ks/seafield/internal/vps"
)

// sealVPSCredential seals a provider key pair for put-vps-account
// (devel/design/vps-nodes.md §2). Only a current voter holding the cluster
// master key can do it; the plain pair is cleared by the caller and never
// written anywhere here.
func (r *Runtime) sealVPSCredential(ctx context.Context, session access.Session, q userauth.VPSCredentialInput) (vps.SealedCredential, error) {
	r.life.RLock()
	defer r.life.RUnlock()
	if r.closed || r.reports == nil {
		return vps.SealedCredential{}, sfcp.ErrAdmission
	}
	view, err := r.physicalOwners()[0].currentView(ctx)
	if err != nil || view.Local || r.controlPolicy.VPSAllowed(view.State, session, time.Now().Unix(), "put-vps-account") != nil {
		return vps.SealedCredential{}, sfcp.ErrAdmission
	}
	members, err := r.controlPolicy.Members(view.State)
	if err != nil || !members.VoterKey(r.commandIdentity().Public) {
		return vps.SealedCredential{}, sfcp.ErrAdmission
	}
	master, err := r.certificateMaster()
	if err != nil {
		return vps.SealedCredential{}, sfcp.ErrAdmission
	}
	key, err := vps.DeriveKey(master, q.Account)
	clear(master)
	if err != nil {
		return vps.SealedCredential{}, sfcp.ErrAdmission
	}
	defer clear(key)
	// Every key pair gets a fresh account SSH key, made here and sealed
	// with it, for servers installed over SSH (devel/design/vps-nodes.md §4).
	seed := make([]byte, ed25519.SeedSize)
	if _, err := rand.Read(seed); err != nil {
		return vps.SealedCredential{}, sfcp.ErrAdmission
	}
	c := vps.Credential{AccessKey: string(q.AccessKey), SecretKey: string(q.SecretKey), SSHSeed: hex.EncodeToString(seed)}
	clear(seed)
	return vps.Seal(r.controlPolicy.Cluster, q.Account, q.Request, c, key, r.commandIdentity().Private)
}

// readVPSOffer reads an account's live catalogue for the "new VPS node"
// form. It needs the same authority as create-vps-node and a voter that can
// open the key; nothing is written.
func (r *Runtime) readVPSOffer(ctx context.Context, session access.Session, q control.VPSOfferQuery) (control.VPSOffer, error) {
	r.life.RLock()
	defer r.life.RUnlock()
	if r.closed || r.reports == nil || !q.Valid() {
		return control.VPSOffer{}, sfcp.ErrAdmission
	}
	view, err := r.physicalOwners()[0].currentView(ctx)
	if err != nil || view.Local || r.controlPolicy.VPSAllowed(view.State, session, time.Now().Unix(), "create-vps-node") != nil {
		return control.VPSOffer{}, sfcp.ErrAdmission
	}
	members, err := r.controlPolicy.Members(view.State)
	if err != nil || !members.VoterKey(r.commandIdentity().Public) {
		return control.VPSOffer{}, sfcp.ErrAdmission
	}
	catalog, err := r.controlPolicy.VPS(view.State)
	if err != nil {
		return control.VPSOffer{}, sfcp.ErrAdmission
	}
	account, ok := catalog.Account(q.Account)
	if !ok {
		return control.VPSOffer{}, sfcp.ErrAdmission
	}
	vendor, ok := vps.Lookup(account.Vendor)
	if !ok {
		return control.VPSOffer{}, sfcp.ErrAdmission
	}
	cred, err := r.vpsCredential(account)
	if err != nil {
		return control.VPSOffer{}, sfcp.ErrAdmission
	}
	return readVPSOffer(ctx, vendor.New(cred, r.vpsEnv), q, time.Now())
}

func readVPSOffer(ctx context.Context, p vps.Provider, q control.VPSOfferQuery, now time.Time) (control.VPSOffer, error) {
	out := control.VPSOffer{Account: q.Account, At: now.Unix()}
	var err error
	if out.Zones, err = p.Zones(ctx); err != nil {
		return control.VPSOffer{}, err
	}
	if out.Images, err = p.Images(ctx, q.Zone); err != nil {
		return control.VPSOffer{}, err
	}
	fq := q.Flavors
	if q.Zone != "" && len(fq.Zones) == 0 {
		fq.Zones = []string{q.Zone}
	}
	if out.Flavors, err = p.Flavors(ctx, fq); err != nil {
		return control.VPSOffer{}, err
	}
	if out.SSHKeys, err = p.SSHKeys(ctx); err != nil {
		return control.VPSOffer{}, err
	}
	if out.Scripts, err = p.Scripts(ctx); err != nil {
		return control.VPSOffer{}, err
	}
	return out, nil
}
