// SPDX-License-Identifier: Apache-2.0

package control

import (
	"bytes"

	"github.com/jay94ks/seafield/internal/access"
	"github.com/jay94ks/seafield/internal/cluster/state"
	"github.com/jay94ks/seafield/internal/secrets"
)

// Both app inputs and source readers use the same Vault approval machinery.
// The signed purpose keeps these namespaces cryptographically separate.
func (p Policy) approvalUsesFor(s state.State, session access.Session, at int64, origin *UserOperation, selection *AppApprovalSelection) (map[string][]secrets.Use, error) {
	if origin != nil && origin.Change.Action == "put-build-context" {
		return p.automaticImageBuildApprovalUses(s, session, at, origin, selection)
	}
	if origin != nil && origin.Change.Action == "begin-image-build" {
		return p.imageBuildApprovalUses(s, session, at, origin, selection)
	}
	if origin == nil || origin.Change.Action != "bind-external-registry" {
		b, err := p.appApprovalBlueprintFor(s, session, at, origin, selection)
		if err != nil {
			return nil, err
		}
		return b.ApprovalUses(origin.Session.Key)
	}
	if selection != nil || origin.VerifyOriginal(p.Cluster) != nil || origin.Session.User != session.User || origin.Change.Principal != session.User || at < origin.At {
		return nil, access.ErrDenied
	}
	var bind ExternalRegistryBind
	if canonical(origin.Change.Payload, &bind) != nil {
		return nil, access.ErrDenied
	}
	c, err := p.Catalog(s)
	if err != nil {
		return nil, err
	}
	for _, action := range []access.Action{access.ManageRegistry, access.Deploy} {
		if c.AuthorizeSession(session, p.Cluster, p.Issuer(session.Issuer), at, bind.Tenant, action, bind.Node) != nil || c.AuthorizeAccepted(origin.Session, p.Cluster, origin.At, bind.Tenant, action, bind.Node) != nil {
			return nil, access.ErrDenied
		}
	}
	if c.OperationAllowed(session, "bind-external-registry") != nil || c.OperationAllowed(origin.Session, "bind-external-registry") != nil {
		return nil, access.ErrDenied
	}
	entries, err := p.ExternalRegistries(s)
	if err != nil {
		return nil, err
	}
	for _, entry := range entries {
		if entry.Spec.Tenant != bind.Tenant || entry.Spec.ID != bind.ID {
			continue
		}
		if entry.Deleted || !entry.Spec.Enabled || ExternalRegistryDefinition(entry.Spec) != bind.Definition {
			return nil, access.ErrDenied
		}
		var owner [32]byte
		if reader := entry.Reader; reader != nil {
			if reader.Draining || !bytes.Equal(OperationBytes(reader.Origin), OperationBytes(*origin)) || !bytes.Equal(reader.Origin.Signature, origin.Signature) {
				return nil, access.ErrDenied
			}
			owner = reader.Owner
		} else {
			if origin.Change.Expected != entry.Revision || origin.RootRevision != s.Object(ExternalRegistriesKey).Revision || origin.Epoch != s.ModuleEpoch() {
				return nil, access.ErrConflict
			}
			owner, err = p.workNodeOwner(s, bind.Node)
			if err != nil {
				return nil, err
			}
		}
		uses := map[string][]secrets.Use{}
		for realm, use := range externalRegistryUses(entry.Spec, *origin, bind.Node, owner) {
			uses[realm] = []secrets.Use{use}
		}
		return uses, nil
	}
	return nil, access.ErrDenied
}
