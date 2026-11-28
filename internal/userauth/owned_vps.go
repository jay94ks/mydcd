// SPDX-License-Identifier: Apache-2.0

package userauth

import (
	"context"
	"time"

	"github.com/jay94ks/seafield/internal/access"
	"github.com/jay94ks/seafield/internal/cluster"
	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/sfcp"
)

// OwnedVPSReply is the owned VPS screen and the two root revisions a write
// pins: RootRevision for attach/detach/set-owned-vps, AccountRootRevision
// for put/remove-vps-account of an owned vendor's account.
type OwnedVPSReply struct {
	Page                control.OwnedVPSPage
	RootRevision        uint64
	AccountRootRevision uint64
	// Status is the leader's vendor readings (asked with Status).
	Status *control.OwnedVPSStatus `json:",omitempty"`
	// Instances is the asked account's VMs (asked with Instances).
	Instances *[]control.OwnedVPSInstance `json:",omitempty"`
}

// OwnedVPSMethod reads the owned VPS servers and the Owned-vendor accounts
// (system administrators). It is apart from VPSMethod, which shows only
// managed accounts and servers (Jay 2026-11-28 14:04 KST).
var OwnedVPSMethod = define(Method[control.OwnedVPSQuery, OwnedVPSReply]{Name: "owned-vps"}, true, func(ctx context.Context, s Service, view cluster.View, session access.Session, q control.OwnedVPSQuery) (OwnedVPSReply, string) {
	page, err := s.Policy.OwnedVPSPage(view.State, session, time.Now().Unix(), q)
	if err != nil {
		return OwnedVPSReply{}, "denied"
	}
	reply := OwnedVPSReply{Page: page, RootRevision: view.State.Object(control.OwnedVPSKey).Revision, AccountRootRevision: view.State.Object(control.VPSKey).Revision}
	if q.Status {
		if s.OwnedVPSStatusReader == nil {
			return OwnedVPSReply{}, "unavailable"
		}
		status, err := s.OwnedVPSStatusReader(ctx)
		if err != nil {
			return OwnedVPSReply{}, "unavailable"
		}
		reply.Status = &status
	}
	if q.Instances != "" {
		if s.OwnedVPSInstancesReader == nil {
			return OwnedVPSReply{}, "unavailable"
		}
		list, err := s.OwnedVPSInstancesReader(ctx, q.Instances)
		if err != nil {
			return OwnedVPSReply{}, "unavailable"
		}
		reply.Instances = &list
	}
	return reply, "ok"
})

// QueryOwnedVPS reads the owned VPS screen through target; with status
// also the leader's vendor readings ("unavailable" when it cannot be
// reached).
func (c Client) QueryOwnedVPS(ctx context.Context, target sfcp.Peer, session access.Session, status bool) (OwnedVPSReply, error) {
	return call(ctx, c, target, session, OwnedVPSMethod, control.OwnedVPSQuery{Status: status})
}

// QueryOwnedVPSInstances reads the owned VPS screen and the VMs in account
// for the attach picker ("unavailable" when the leader or the vendor cannot
// be read now).
func (c Client) QueryOwnedVPSInstances(ctx context.Context, target sfcp.Peer, session access.Session, account string) (OwnedVPSReply, error) {
	return call(ctx, c, target, session, OwnedVPSMethod, control.OwnedVPSQuery{Instances: account})
}
