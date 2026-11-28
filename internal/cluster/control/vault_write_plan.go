// SPDX-License-Identifier: Apache-2.0

package control

import (
	"encoding/hex"
	"slices"

	"github.com/jay94ks/seafield/internal/access"
	"github.com/jay94ks/seafield/internal/cluster/state"
	"github.com/jay94ks/seafield/internal/config"
	"github.com/jay94ks/seafield/internal/secrets"
)

type VaultWritePlanRequest struct {
	Realm, ID, Object, Profile string
	Kind                       secrets.WriteKind
	Keys                       []string
}
type VaultWritePlan struct {
	Schema                                 uint8
	Realm                                  string
	RootRevision, TreeRevision, WriteEpoch uint64
	Request                                secrets.WriteRequest
	Object                                 *secrets.Object           `json:",omitempty"`
	Write                                  *VaultWriteView           `json:",omitempty"`
	Observation                            *secrets.WriteObservation `json:",omitempty"`
	Receiver                               *config.Peer              `json:",omitempty"`
	// Voters, for a builtin write no voter has reported yet: any of them
	// may take the values. The client picks one it reaches and keeps it.
	Voters []config.Peer `json:",omitempty"`
}

func (p Policy) PlanVaultWrite(s state.State, session access.Session, at int64, q VaultWritePlanRequest) (VaultWritePlan, error) {
	p, err := p.Current(s)
	if err != nil {
		return VaultWritePlan{}, ErrCatalog
	}
	c, err := p.Catalog(s)
	if err != nil {
		return VaultWritePlan{}, err
	}
	action := access.ManageSecrets
	if q.Realm == "" {
		action = access.ManageCluster
	}
	if c.AuthorizeSession(session, p.Cluster, p.Issuer(session.Issuer), at, q.Realm, action, "") != nil {
		return VaultWritePlan{}, access.ErrDenied
	}
	v, err := p.Vault(s)
	if err != nil {
		return VaultWritePlan{}, err
	}
	tree, ok := v.Trees[q.Realm]
	if !ok {
		return VaultWritePlan{}, ErrCatalog
	}
	plan := VaultWritePlan{Schema: 1, Realm: q.Realm, RootRevision: s.Object(VaultKey).Revision, TreeRevision: tree.Revision(), WriteEpoch: tree.WriteEpoch()}
	var profile secrets.WriteProfile
	if old, exists := tree.Write(q.ID); exists {
		if old.Actor != session.User && !c.SystemAllowed(session.User) {
			return plan, access.ErrDenied
		}
		keys := slices.Clone(q.Keys)
		slices.Sort(keys)
		if q.Object != "" && q.Object != old.Request.Object || q.Profile != "" && q.Profile != old.Request.Profile || q.Kind != "" && q.Kind != old.Request.Kind || len(keys) != 0 && !slices.Equal(keys, old.Request.Keys) {
			return plan, ErrCatalog
		}
		public := publicVaultWrite(old)
		plan.Write, plan.Request, plan.Observation = &public, old.Request, old.Observation
		profile, _ = tree.WriteProfile(old.Request.Profile)
	} else {
		if q.Object == "" && q.Kind == "" {
			plan.Request = secrets.WriteRequest{ID: q.ID}
			return plan, nil
		}
		plan.Request, err = tree.PlanWrite(c, session.User, q.ID, q.Object, q.Profile, q.Kind, q.Keys)
		if err != nil {
			return plan, err
		}
		profile, _ = tree.WriteProfile(plan.Request.Profile)
	}
	if object, ok := tree.Object(plan.Request.Object); ok {
		plan.Object = &object
	}
	members, err := p.Members(s)
	if err != nil {
		return plan, err
	}
	if profile.Builtin() {
		// The voter that signed the observation holds the original sealed
		// value; before one exists, the first current voter writes it.
		voters := members.SessionIssuers()
		reported := plan.Observation != nil && members.VoterKey(plan.Observation.Reporter)
		if reported {
			voters = [][32]byte{plan.Observation.Reporter}
		}
		for _, key := range voters {
			for _, e := range members.Entries {
				if e.CurrentPeer().Key == hex.EncodeToString(key[:]) {
					peer := e.CurrentPeer()
					if plan.Receiver == nil {
						plan.Receiver = &peer
					}
					if !reported {
						plan.Voters = append(plan.Voters, peer)
					}
				}
			}
		}
		if plan.Receiver != nil {
			return plan, nil
		}
		if plan.Write == nil {
			return plan, access.ErrDenied
		}
		return plan, nil
	}
	entry, found := members.Entry(profile.Node)
	if plan.Write == nil && (!found || !members.WorkKey(profile.Key)) {
		return plan, access.ErrDenied
	}
	if profile.Enabled && found && members.MemberKey(profile.Key) && entry.CurrentPeer().Key == hex.EncodeToString(profile.Key[:]) {
		peer := entry.CurrentPeer()
		plan.Receiver = &peer
	}
	return plan, nil
}
