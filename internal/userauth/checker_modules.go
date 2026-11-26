// SPDX-License-Identifier: Apache-2.0

package userauth

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"slices"

	"github.com/jay94ks/mydcd/internal/access"
	"github.com/jay94ks/mydcd/internal/mydcp"
	checker "github.com/jay94ks/mydcd/internal/workload/lifecycle"
)

func moduleInput(d checker.SourceDescriptor, pin checker.ModulePin) bool {
	return d.Validate() == nil && slices.Contains(d.Modules, pin) && pin.Length <= checker.MaxModuleBytes
}

func (c Client) moduleReply(target mydcp.Peer, d checker.SourceDescriptor, pin checker.ModulePin, reply Reply) (checker.ModuleFact, error) {
	fact := reply.CheckerModule
	if reply.Code != "ok" || reply.Tenant != d.Tenant || reply.Node != hex.EncodeToString(target.Key[:]) || reply.CheckerSource != nil || fact == nil || fact.Verify() != nil || fact.Cluster != c.Cluster || fact.Owner != [32]byte(target.Key) || fact.Tenant != d.Tenant || fact.Module != pin {
		return checker.ModuleFact{}, mydcp.ErrAdmission
	}
	return fact.Clone(), nil
}

func (c Client) StageCheckerModule(ctx context.Context, target mydcp.Peer, session access.Session, d checker.SourceDescriptor, archive checker.ModuleArchive) (checker.ModuleFact, error) {
	if c.Verify(session) != nil || !moduleInput(d, archive.Pin) || archive.Pin.Length != uint64(len(archive.ZIP)) || sha256.Sum256(archive.ZIP) != archive.Pin.Digest {
		return checker.ModuleFact{}, mydcp.ErrAdmission
	}
	d = d.Clone()
	pin := archive.Pin
	reply, err := c.stageCheckerArtifact(ctx, target, session, Request{CheckerUpload: c.checkerUpload, Method: "checker-module-stage", Tenant: d.Tenant, CheckerSource: &d, CheckerModule: &pin}, archive.ZIP)
	if err != nil {
		return checker.ModuleFact{}, err
	}
	return c.moduleReply(target, d, pin, reply)
}

func (c Client) RecoverCheckerModule(ctx context.Context, target mydcp.Peer, session access.Session, d checker.SourceDescriptor, pin checker.ModulePin) (checker.ModuleFact, error) {
	if c.Verify(session) != nil || !moduleInput(d, pin) {
		return checker.ModuleFact{}, mydcp.ErrAdmission
	}
	d = d.Clone()
	body, err := requestBody(Request{CheckerUpload: c.checkerUpload, Method: "checker-module-recover", Tenant: d.Tenant, CheckerSource: &d, CheckerModule: &pin})
	if err != nil {
		return checker.ModuleFact{}, err
	}
	reply, _, err := c.exchange(ctx, target, func(conn *mydcp.Session) (Envelope, error) {
		return Envelope{Body: body, Session: &session, Signature: ed25519.Sign(c.Self.Private, access.RequestBytes(session, conn.PeerChallenge(), body))}, nil
	}, false)
	if err != nil {
		return checker.ModuleFact{}, err
	}
	return c.moduleReply(target, d, pin, reply)
}
