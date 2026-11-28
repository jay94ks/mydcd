// SPDX-License-Identifier: Apache-2.0

package control

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"slices"
	"strconv"
	"strings"

	"github.com/jay94ks/seafield/internal/cluster/lifecycle"
	"github.com/jay94ks/seafield/internal/cluster/state"
	"github.com/jay94ks/seafield/internal/deployment"
	"github.com/jay94ks/seafield/internal/network"
	"github.com/jay94ks/seafield/internal/network/services"
)

func retirementTarget(i deployment.Inventory, key string) (deployment.RetirementTarget, bool) {
	r, ok := i.Retirement()
	if !ok {
		return deployment.RetirementTarget{}, false
	}
	for _, t := range r.Targets {
		if t.Original.Step.Key == key {
			return t, true
		}
	}
	return deployment.RetirementTarget{}, false
}

func (p Policy) retireAppDNS(s state.State, r AppProgress, a Apps, entry appEntry) (map[string][]byte, state.Code) {
	t, ok := retirementTarget(entry.Inventory, r.Key)
	if !ok || a.network == nil || t.Original.Step.Kind != "dns" || !p.ownsResource(s, r.Reporter, t.Original.Step.Owner) || !entry.Inventory.CanRetire(r.Key) || t.Drain == nil || t.Drain.Result == nil || t.Drain.Result.Code != state.Applied || s.Object(r.Key).Value != t.Drain.Command.Value || p.authorizeAppRemoval(s, entry) != nil {
		return nil, state.ConditionFailed
	}
	projection, err := p.ProjectResources(s)
	if err != nil {
		return nil, state.Invalid
	}
	catalog, err := p.Catalog(s)
	if err != nil {
		return nil, state.Invalid
	}
	n := *a.network
	n.Groups = slices.Clone(n.Groups)
	for index, group := range n.Groups {
		if !slices.ContainsFunc(group.Owners, func(row AppDNSOwner) bool {
			return row.Source.Key == r.Key && row.Source.Generation == t.Original.Result.Generation && row.Config.Enabled
		}) {
			continue
		}
		if n.Revision == ^uint64(0) {
			return nil, state.ConditionFailed
		}
		n.Revision++
		group.Source = n.Revision
		group.Serial++
		group.Owners = slices.Clone(group.Owners)
		for j, row := range group.Owners {
			row.Config.Enabled = false
			row.Config.Source = group.Source
			row.Config.Serial = group.Serial
			ref, known := n.Authority.ReferenceConsumer(row.Reference)
			if !known {
				return nil, state.Invalid
			}
			n.Authority, _, err = n.Authority.GrantDNSInstance(catalog, projection.Resources.Networks, entry.Origin.Session.User, ref.Generation, row.Config)
			if err != nil {
				return nil, state.ConditionFailed
			}
			group.Owners[j] = row
		}
		group.Digest = appDNSDigest(group.Owners)
		n.Groups[index] = group
		a.network = &n
		return p.appsCheckpoint(s, a)
	}
	return nil, state.ConditionFailed
}

func bridgeAllocations(a services.Authority, c deployment.Claim) ([]network.Allocation, error) {
	g, err := deployment.DecodeGoalResources(a.Cluster(), c.Step.Key, state.Object{Present: true, Value: c.Command.Value, Generation: c.Result.Generation, Revision: c.Result.Revision})
	if err != nil || g.Bridge == nil {
		return nil, ErrCatalog
	}
	var out []network.Allocation
	for _, alloc := range a.AddressBook().Checkpoint().Allocations {
		pool, ok := a.AddressBook().Pool(alloc.Pool)
		if ok && pool.Network == g.Goal.Tenant+"/"+g.Bridge.Network {
			out = append(out, alloc)
		}
	}
	return out, nil
}

// NetworkRetirementAllocations reads original ownership, never the entire
// shared pool on behalf of an app borrower. It is shared by the reducer and
// native collector so neither reconstructs a broader cleanup scope.
func (a Apps) NetworkRetirementAllocations(tenant, app, key string) ([]network.Allocation, error) {
	entry, exists := a.entries[appKey(tenant, app)]
	if !exists {
		return nil, ErrCatalog
	}
	target, exists := retirementTarget(entry.Inventory, key)
	if !exists || target.Original.Step.Kind != "bridge" && target.Original.Step.Kind != "network-ref" && (target.Original.Step.Kind != "task" || !target.Closed) {
		return nil, ErrCatalog
	}
	if a.network == nil {
		return nil, nil
	}
	if target.Original.Step.Kind != "task" {
		return a.retirementNetworkAllocations(entry, target.Original)
	}
	// A positively closed Task owns only its original endpoint allocations,
	// even when the shared network reference remains live for another Task.
	var out []network.Allocation
	for _, claim := range entry.Inventory.Claims() {
		if claim.Step.Kind != "bridge" && claim.Step.Kind != "network-ref" {
			continue
		}
		rows, err := a.retirementNetworkAllocations(entry, claim)
		if err != nil {
			return nil, err
		}
		for _, allocation := range rows {
			if strings.HasPrefix(allocation.Endpoint, key+"/") {
				if allocation.Generation != target.Original.Result.Generation {
					return nil, ErrCatalog
				}
				out = append(out, allocation)
			}
		}
	}
	slices.SortFunc(out, func(a, b network.Allocation) int { return strings.Compare(a.Endpoint, b.Endpoint) })
	return out, nil
}

func (a Apps) retirementNetworkAllocations(entry appEntry, c deployment.Claim) ([]network.Allocation, error) {
	if c.Step.Kind == "bridge" {
		return bridgeAllocations(a.network.Authority, c)
	}
	scope := entry.Inventory.Scope()
	tenant, app, key := scope.Tenant, scope.App, c.Step.Key
	var goal deployment.GoalCommand
	var ref deployment.NetworkReference
	if canonical([]byte(c.Command.Value), &goal) != nil || goal.Kind != "network-ref" || goal.Tenant != tenant || goal.App != app || canonical(goal.Config, &ref) != nil || ref.Tenant != tenant || ref.Node != goal.Node || ref.Owner != goal.Owner {
		return nil, ErrCatalog
	}
	retirement, _ := entry.Inventory.Retirement()
	dependency := deployment.ObjectRef{Key: key, Generation: c.Result.Generation, Revision: c.Result.Revision}
	var out []network.Allocation
	for _, candidate := range retirement.Targets {
		task := candidate.Original
		if task.Step.Kind != "task" || task.Step.Node != goal.Node {
			continue
		}
		var original deployment.GoalCommand
		var service deployment.ComposeService
		if canonical([]byte(task.Command.Value), &original) != nil || original.Tenant != tenant || original.App != app || original.Node != goal.Node || original.Owner != task.Step.Owner || !lifecycle.ResourceIdentity(a.network.Authority.Cluster(), original.Node, original.Owner, goal.Owner, original.ResourceKeys) || json.Unmarshal(original.Config, &service) != nil {
			return nil, ErrCatalog
		}
		if !slices.Contains(original.Dependencies, dependency) {
			continue
		}
		for alias, attachment := range service.Networks {
			if deployment.ResourceKey("network-ref", tenant, app, alias+"/"+goal.Node) != key {
				continue
			}
			for family, address := range []string{attachment.IPv4, attachment.IPv6} {
				if address == "" {
					continue
				}
				endpoint := task.Step.Key + "/" + alias + "/" + strconv.Itoa(family)
				allocation, held := a.network.Authority.AddressBook().AllocationOf(endpoint, task.Result.Generation)
				if !held {
					continue
				}
				pool, exists := a.network.Authority.AddressBook().Pool(allocation.Pool)
				if !exists || pool.Network != tenant+"/"+ref.Network || allocation.Generation != task.Result.Generation || allocation.Address.String() != address || allocation.Owner != hex.EncodeToString(goal.Owner[:]) {
					return nil, ErrCatalog
				}
				out = append(out, allocation)
			}
		}
	}
	slices.SortFunc(out, func(a, b network.Allocation) int { return strings.Compare(a.Endpoint, b.Endpoint) })
	return out, nil
}

func closedAddressTask(i deployment.Inventory, a network.Allocation, owner [32]byte) (deployment.RetirementTarget, bool) {
	r, ok := i.Retirement()
	if !ok {
		return deployment.RetirementTarget{}, false
	}
	for _, t := range r.Targets {
		c := t.Original
		if c.Step.Kind == "task" && c.Result.Generation == a.Generation && strings.HasPrefix(a.Endpoint, c.Step.Key+"/") && t.Closed && closedTaskPacketOwner(i, c, a, owner) {
			return t, true
		}
	}
	return deployment.RetirementTarget{}, false
}

func (p Policy) retireAppAddresses(s state.State, r AppProgress, a Apps, entry appEntry) (map[string][]byte, state.Code) {
	writes, code, _ := p.retireAppAddressesWhy(s, r, a, entry)
	return writes, code
}

// ExplainAddressRetirement names the first condition a retire-addresses report
// fails against s. Result codes carry no text, so the reporting node replays
// the reducer on its own view to log why a report keeps being rejected. It
// returns "" when the report would apply.
func (p Policy) ExplainAddressRetirement(s state.State, r AppProgress) string {
	a, err := p.readOnlyApps(s)
	if err != nil {
		return "apps unreadable: " + err.Error()
	}
	entry, ok := a.entries[appKey(r.Tenant, r.App)]
	if !ok {
		return "app not found"
	}
	if retirement, ok := entry.Inventory.Retirement(); !ok || retirement.ID != r.Operation {
		return "no retirement with this operation"
	}
	if r.Retire == nil {
		return "report has no retirement payload"
	}
	_, code, why := p.retireAppAddressesWhy(s, r, a, entry)
	if code == state.Applied {
		return ""
	}
	return why
}

func (p Policy) retireAppAddressesWhy(s state.State, r AppProgress, a Apps, entry appEntry) (map[string][]byte, state.Code, string) {
	t, ok := retirementTarget(entry.Inventory, r.Key)
	closedTask := ok && t.Original.Step.Kind == "task" && t.Closed
	switch {
	case !ok:
		return nil, state.ConditionFailed, "key is not a retirement target"
	case a.network == nil:
		return nil, state.ConditionFailed, "no network authority"
	case !closedTask && t.Original.Step.Kind != "bridge" && t.Original.Step.Kind != "network-ref":
		return nil, state.ConditionFailed, "target " + t.Original.Step.Kind + " is not a closed task, bridge or network-ref"
	case !closedTask && !entry.Inventory.CanRetire(r.Key):
		return nil, state.ConditionFailed, "target cannot retire yet (dependents still open)"
	case !p.ownsResource(s, r.Reporter, t.Original.Step.Owner):
		return nil, state.ConditionFailed, "reporter does not own the target"
	case p.authorizeAppRemoval(s, entry) != nil:
		return nil, state.ConditionFailed, "app removal is not authorized"
	}
	allocations, err := a.NetworkRetirementAllocations(r.Tenant, r.App, r.Key)
	if err != nil {
		return nil, state.ConditionFailed, "allocations: " + err.Error()
	}
	if len(allocations) == 0 {
		return nil, state.ConditionFailed, "target has no allocations left"
	}
	projection, err := p.ProjectResources(s)
	if err != nil {
		return nil, state.Invalid, "projection: " + err.Error()
	}
	catalog, err := p.Catalog(s)
	if err != nil {
		return nil, state.Invalid, "catalog: " + err.Error()
	}
	n := *a.network
	changed, held := 0, 0
	for _, alloc := range allocations {
		at := " (address " + alloc.Address.String() + " endpoint " + alloc.Endpoint + ")"
		raw, decodeErr := hex.DecodeString(alloc.Owner)
		var owner [32]byte
		if decodeErr != nil || len(raw) != 32 {
			return nil, state.ConditionFailed, "allocation owner is not a key" + at
		}
		copy(owner[:], raw)
		original, known := closedAddressTask(entry.Inventory, alloc, owner)
		var taskGoal deployment.GoalCommand
		switch {
		case !known:
			return nil, state.ConditionFailed, "no closed task target owns the allocation" + at
		case canonical([]byte(original.Original.Command.Value), &taskGoal) != nil:
			return nil, state.ConditionFailed, "task command is not canonical" + at
		case !p.taskPacketLineage(s, taskGoal, owner):
			return nil, state.ConditionFailed, "task resource key lineage does not match the allocation owner" + at
		case !p.ownsResource(s, r.Reporter, original.Original.Step.Owner) || !p.ownsResource(s, r.Reporter, owner):
			return nil, state.ConditionFailed, "reporter does not own the task or allocation" + at
		}
		f, fenced := n.Authority.AddressRetirement(alloc)
		if r.Retire.Phase == "fence" {
			if fenced {
				held++
				continue
			}
			n.Authority, err = n.Authority.BeginStaticRetirement(catalog, projection.Resources.Networks, entry.Origin.Session.User, n.Authority.Revision(), alloc, int64(r.At))
		} else {
			if !fenced {
				return nil, state.ConditionFailed, "release for an address that is not fenced" + at
			}
			proof, found := services.AddressOwnerClose{}, false
			for _, candidate := range r.Retire.Addresses {
				if candidate.Target == f.ID {
					if found {
						return nil, state.ConditionFailed, "duplicate release proof" + at
					}
					proof, found = candidate, true
				}
			}
			if !found {
				continue
			}
			if proof.Native != original.Original.ClosedNative() || proof.Owner != owner {
				return nil, state.ConditionFailed, "release proof native or owner differs from the task" + at
			}
			if !n.Authority.AddressConsumersSettled(alloc) {
				return nil, state.ConditionFailed, "address consumers are not settled" + at
			}
			if proof.At < f.At || proof.At > int64(r.At) {
				return nil, state.ConditionFailed, fmt.Sprintf("release proof time %d outside fence %d..report %d", proof.At, f.At, r.At) + at
			}
			n.Authority, err = n.Authority.ReleaseStatic(alloc, proof, int64(r.At))
		}
		if err != nil {
			return nil, state.ConditionFailed, r.Retire.Phase + ": " + err.Error() + at
		}
		changed++
		if r.Retire.Phase == "fence" && changed == 16 {
			break
		}
	}
	if changed == 0 {
		return nil, state.ConditionFailed, fmt.Sprintf("%s changed nothing (%d allocations, %d already fenced)", r.Retire.Phase, len(allocations), held)
	}
	if r.Retire.Phase == "release" && changed != len(r.Retire.Addresses) {
		return nil, state.ConditionFailed, fmt.Sprintf("release matched %d of %d proofs", changed, len(r.Retire.Addresses))
	}
	a.network = &n
	writes, code := p.appsCheckpoint(s, a)
	return writes, code, "checkpoint rejected"
}

func (p Policy) closeAppNetwork(s state.State, r AppProgress, a Apps, entry appEntry) (Apps, error) {
	t, ok := retirementTarget(entry.Inventory, r.Key)
	if !ok {
		return a, ErrCatalog
	}
	if t.Original.Step.Kind != "dns" && r.Retire.DNS != nil || t.Original.Step.Kind != "bridge" && r.Retire.Network != nil {
		return a, ErrCatalog
	}
	if a.network == nil {
		if r.Retire.DNS != nil || r.Retire.Network != nil {
			return a, ErrCatalog
		}
		return a, nil
	}
	n := *a.network
	if t.Original.Step.Kind == "network-ref" {
		allocations, err := a.NetworkRetirementAllocations(r.Tenant, r.App, r.Key)
		if err != nil || len(allocations) != 0 {
			return a, ErrCatalog
		}
	}
	if t.Original.Step.Kind == "dns" {
		if r.Retire.DNS == nil || r.Retire.DNS.Target != ([32]byte{}) {
			return a, ErrCatalog
		}
		_, rows, _ := a.NetworkDNS(t.Original.Step.Owner)
		found := false
		for _, row := range rows {
			if row.Source.Key == r.Key && row.Source.Generation == t.Original.Result.Generation && row.Reference == r.Retire.DNS.Consumer && !row.Config.Enabled {
				found = true
			}
		}
		if !found {
			return a, ErrCatalog
		}
		var err error
		n.Authority, err = n.Authority.ObserveReferenceClose(*r.Retire.DNS, int64(r.At))
		if err != nil {
			return a, err
		}
	}
	if t.Original.Step.Kind == "bridge" {
		g, err := deployment.DecodeGoalResources(p.Cluster, r.Key, state.Object{Present: true, Value: t.Original.Command.Value, Generation: t.Original.Result.Generation, Revision: t.Original.Result.Revision})
		if err != nil {
			return a, err
		}
		_, held := n.Authority.AddressBook().Pool(g.Goal.Tenant + "/" + g.Network.ID + "/pool")
		if held {
			if r.Retire.Network == nil {
				return a, ErrCatalog
			}
			projection, err := p.ProjectResources(s)
			if err != nil {
				return a, err
			}
			catalog, err := p.Catalog(s)
			if err != nil {
				return a, err
			}
			n.Authority, _, err = n.Authority.RetireNetwork(catalog, projection.Resources.Networks, entry.Origin.Session.User, *r.Retire.Network)
			if err != nil {
				return a, err
			}
			// Archive compacts only positively closed references. Remove their
			// owner projections in this SAME transaction; never leave dangling
			// IDs. Keep the group's serial floor after its last owner is gone:
			// the same DNS scope's local journal and client caches outlive a Bridge.
			n.Groups = slices.Clone(n.Groups)
			for i, group := range n.Groups {
				group.Owners = slices.Clone(group.Owners)
				group.Owners = slices.DeleteFunc(group.Owners, func(row AppDNSOwner) bool { _, known := n.Authority.ReferenceConsumer(row.Reference); return !known })
				group.Digest = appDNSDigest(group.Owners)
				n.Groups[i] = group
			}
		}
	}
	a.network = &n
	return a, nil
}

// A network allocation belongs to the Task's frozen attachment, not its
// signing key. Read immutable claims: a draining/deleted current source cannot
// replace the original Task read-set during positive closure collection.
func closedTaskPacketOwner(i deployment.Inventory, c deployment.Claim, allocation network.Allocation, owner [32]byte) bool {
	scope := i.Scope()
	var task deployment.GoalCommand
	var service deployment.ComposeService
	if canonical([]byte(c.Command.Value), &task) != nil || task.Schema != 1 || task.Cluster != scope.Cluster || task.Kind != "task" || task.Tenant != scope.Tenant || task.App != scope.App || task.Deployment != scope.Deployment || task.Node != c.Step.Node || task.Owner != c.Step.Owner || canonical(task.Config, &service) != nil || !lifecycle.ResourceIdentity(scope.Cluster, task.Node, task.Owner, owner, task.ResourceKeys) {
		return false
	}
	suffix, ok := strings.CutPrefix(allocation.Endpoint, c.Step.Key+"/")
	parts := strings.Split(suffix, "/")
	if !ok || len(parts) != 2 {
		return false
	}
	family, err := strconv.Atoi(parts[1])
	if err != nil || family < 0 || family > 1 {
		return false
	}
	attachment, exists := service.Networks[parts[0]]
	if !exists || []string{attachment.IPv4, attachment.IPv6}[family] != allocation.Address.String() {
		return false
	}
	for _, parent := range i.Claims() {
		bridgeKey := deployment.ResourceKey("bridge", task.Tenant, task.App, parts[0]+"/"+task.Node)
		refKey := deployment.ResourceKey("network-ref", task.Tenant, task.App, parts[0]+"/"+task.Node)
		if parent.Step.Key != bridgeKey && parent.Step.Key != refKey {
			continue
		}
		dependency := deployment.ObjectRef{Key: parent.Step.Key, Generation: parent.Result.Generation, Revision: parent.Result.Revision}
		if !slices.Contains(task.Dependencies, dependency) || parent.Step.Owner != owner || parent.Step.Node != task.Node {
			continue
		}
		var goal deployment.GoalCommand
		if canonical([]byte(parent.Command.Value), &goal) != nil || goal.Cluster != task.Cluster || goal.Tenant != task.Tenant || goal.App != task.App || goal.Deployment != task.Deployment || goal.Node != task.Node || goal.Owner != owner {
			continue
		}
		if parent.Step.Key == refKey {
			var ref deployment.NetworkReference
			if goal.Kind == "network-ref" && canonical(goal.Config, &ref) == nil && ref.RetainSource && ref.Owner == owner && ref.Tenant == task.Tenant && ref.Node == task.Node {
				return true
			}
		} else {
			decoded, err := deployment.DecodeGoalResources(task.Cluster, parent.Step.Key, state.Object{Present: true, Value: parent.Command.Value, Generation: parent.Result.Generation, Revision: parent.Result.Revision})
			if err == nil && decoded.Bridge != nil {
				return true
			}
		}
	}
	return false
}
