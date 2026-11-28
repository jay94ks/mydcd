// SPDX-License-Identifier: Apache-2.0

package userauth

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"slices"

	"github.com/jay94ks/seafield/internal/access"
	"github.com/jay94ks/seafield/internal/sfcp"
	checker "github.com/jay94ks/seafield/internal/workload/lifecycle"
)

func moduleInput(d checker.SourceDescriptor, pin checker.ModulePin) bool {
	return d.Validate() == nil && slices.Contains(d.Modules, pin) && pin.Length <= checker.MaxModuleBytes
}

func (c Client) moduleReply(target sfcp.Peer, d checker.SourceDescriptor, pin checker.ModulePin, reply Reply) (checker.ModuleFact, error) {
	var value checker.ModuleFact
	fact := &value
	if reply.Code != "ok" || len(reply.Data) == 0 || strict(reply.Data, fact) != nil || reply.Node != hex.EncodeToString(target.Key[:]) || fact.Verify() != nil || fact.Cluster != c.Cluster || fact.Owner != [32]byte(target.Key) || fact.Tenant != d.Tenant || fact.Module != pin {
		return checker.ModuleFact{}, sfcp.ErrAdmission
	}
	return fact.Clone(), nil
}

func (c Client) StageCheckerModule(ctx context.Context, target sfcp.Peer, session access.Session, d checker.SourceDescriptor, archive checker.ModuleArchive) (checker.ModuleFact, error) {
	if c.Verify(session) != nil || !moduleInput(d, archive.Pin) || archive.Pin.Length != uint64(len(archive.ZIP)) || sha256.Sum256(archive.ZIP) != archive.Pin.Digest {
		return checker.ModuleFact{}, sfcp.ErrAdmission
	}
	d = d.Clone()
	pin := archive.Pin
	request, err := c.checkerRequest(CheckerModuleStageMethod.Name, d, &pin)
	if err != nil {
		return checker.ModuleFact{}, err
	}
	reply, err := c.stageCheckerArtifact(ctx, target, session, request, archive.ZIP)
	if err != nil {
		return checker.ModuleFact{}, err
	}
	return c.moduleReply(target, d, pin, reply)
}

func (c Client) RecoverCheckerModule(ctx context.Context, target sfcp.Peer, session access.Session, d checker.SourceDescriptor, pin checker.ModulePin) (checker.ModuleFact, error) {
	if c.Verify(session) != nil || !moduleInput(d, pin) {
		return checker.ModuleFact{}, sfcp.ErrAdmission
	}
	d = d.Clone()
	request, err := c.checkerRequest(CheckerModuleRecoverMethod.Name, d, &pin)
	if err != nil {
		return checker.ModuleFact{}, err
	}
	body, err := requestBody(request)
	if err != nil {
		return checker.ModuleFact{}, err
	}
	reply, _, err := c.exchange(ctx, target, func(conn *sfcp.Session) (Envelope, error) {
		return Envelope{Body: body, Session: &session, Signature: ed25519.Sign(c.Self.Private, access.RequestBytes(session, conn.PeerChallenge(), body))}, nil
	}, false)
	if err != nil {
		return checker.ModuleFact{}, err
	}
	return c.moduleReply(target, d, pin, reply)
}
