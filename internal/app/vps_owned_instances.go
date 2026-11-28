// SPDX-License-Identifier: Apache-2.0

package app

import (
	"context"
	"encoding/json"
	"sort"

	"github.com/jay94ks/seafield/internal/cluster"
	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/schema"
	"github.com/jay94ks/seafield/internal/sfcp"
	"github.com/jay94ks/seafield/internal/vps"
)

// ownedPickerMax bounds the VMs listed (and subscriptions read) per ask.
const ownedPickerMax = 50

// ownedInstancesAsk is the owned-vps-instances read's input.
type ownedInstancesAsk struct{ Account string }

// readOwnedVPSInstances asks the leader for an Owned-vendor account's VMs.
func (r *Runtime) readOwnedVPSInstances(ctx context.Context, account string) ([]control.OwnedVPSInstance, error) {
	raw, err := json.Marshal(ownedInstancesAsk{Account: account})
	if err != nil {
		return nil, err
	}
	reply, err := r.appCall(ctx, "owned-vps-instances", raw)
	if err != nil {
		return nil, err
	}
	var out []control.OwnedVPSInstance
	if reply.Code != "ok" || json.Unmarshal(reply.Data, &out) != nil {
		return nil, errNoAppLeader
	}
	return out, nil
}

// nodeReadOwnedVPSInstances lists the account's VMs from the vendor (the
// leader holds the sealed token; the asking node checked the session).
// Reading changes nothing at the vendor.
func (r *Runtime) nodeReadOwnedVPSInstances(ctx context.Context, method, key string, input []byte, v cluster.View) (json.RawMessage, error) {
	q, err := schema.Decode[ownedInstancesAsk](input)
	if err != nil || v.Local || !r.Engine().IsLeader() {
		return nil, sfcp.ErrAdmission
	}
	accounts, err := r.controlPolicy.VPS(v.State)
	if err != nil {
		return nil, err
	}
	owned, err := r.controlPolicy.OwnedVPS(v.State)
	if err != nil {
		return nil, err
	}
	account, ok := accounts.Account(q.Account)
	if !ok {
		return nil, sfcp.ErrAdmission
	}
	p, err := r.ownedProvider(account)
	if err != nil {
		return nil, err
	}
	list, err := p.Instances(ctx)
	if err != nil {
		return nil, err
	}
	return json.Marshal(ownedPicker(ctx, p, account.Name, list, owned))
}

// ownedPicker shapes the vendor's VMs for the attach picker: by ID, at most
// ownedPickerMax, each with its subscription end when it can be read and the
// record already using it.
func ownedPicker(ctx context.Context, p vps.OwnedProvider, account string, list []vps.Instance, owned control.OwnedVPSCatalog) []control.OwnedVPSInstance {
	used := map[string]string{}
	for _, s := range owned.Servers {
		if s.Account == account {
			used[s.InstanceID] = s.Name
		}
	}
	sort.Slice(list, func(i, j int) bool { return list[i].ID < list[j].ID })
	if len(list) > ownedPickerMax {
		list = list[:ownedPickerMax]
	}
	out := []control.OwnedVPSInstance{}
	for _, inst := range list {
		row := control.OwnedVPSInstance{ID: inst.ID, Plan: inst.Flavor, Zone: inst.Zone, PublicIP: inst.PublicIPv4, Image: inst.Image, Status: string(inst.Status), Attached: used[inst.ID]}
		if sub, err := p.Subscription(ctx, inst.ID); err == nil && !sub.ExpiresAt.IsZero() {
			row.ExpiresAt = sub.ExpiresAt.Unix()
		}
		out = append(out, row)
	}
	return out
}
