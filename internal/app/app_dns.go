// SPDX-License-Identifier: Apache-2.0

package app

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"time"

	"github.com/jay94ks/seafield/internal/cluster"
	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/cluster/state"
	"github.com/jay94ks/seafield/internal/deployment"
	"github.com/jay94ks/seafield/internal/identity"
	"github.com/jay94ks/seafield/internal/network"
	"github.com/jay94ks/seafield/internal/network/services"
	"github.com/jay94ks/seafield/internal/reconcile"
	"github.com/jay94ks/seafield/internal/schema"
	"github.com/jay94ks/seafield/internal/tenancy"
)

func (r *Runtime) currentAppDNS(ctx context.Context, tenant, id string) (services.DNSOwnerPolicy, error) {
	engine := r.Engine()
	v, err := engine.Read(ctx, false)
	if err != nil {
		return services.DNSOwnerPolicy{}, err
	}
	view := dnsPolicyView{engine: engine, cluster: r.controlPolicy.Cluster, owner: r.Identity.Public, index: v.State.Index(), epoch: v.State.ModuleEpoch(), raftIndex: v.RaftIndex, term: v.Term, local: v.Local}
	policy, err := r.dnsPolicies.current(ctx, view, dnsPolicyName{tenant, id}, func() (services.DNSOwnerPolicy, error) {
		p, _, err := r.controlPolicy.AppDNSMaterial(v.State, r.commandIdentity().Public, tenant, id, r.Identity.Public)
		return p, err
	})
	if err != nil {
		return policy, err
	}
	// Freshness changes with wall time even when the committed state index
	// does not. Do not cache serving eligibility with the fixed DNS policy.
	policy.Unavailable, err = r.controlPolicy.AppDNSUnavailable(v.State, policy.Config, uint64(time.Now().Unix()))
	return policy, err
}

func (r *Runtime) appDNSPermit(ctx context.Context, p services.DNSOwnerPolicy) error {
	v, err := r.Engine().Read(ctx, false)
	if err != nil {
		return err
	}
	_, row, err := r.controlPolicy.AppDNSMaterial(v.State, r.commandIdentity().Public, p.Config.Tenant, p.Config.ID, r.Identity.Public)
	if err != nil || !row.Config.Enabled {
		return deployment.ErrInputs
	}
	request := control.NativeRequest{Source: row.Source}
	if row.Managed != nil {
		request.DNS = row.Config.ID
	}
	raw, _ := json.Marshal(request)
	reply, err := r.appCall(ctx, "app-native-permit", raw)
	if err != nil {
		return err
	}
	permit, err := schema.Decode[control.NativePermit](reply.Data)
	if err != nil || permit.Kind != "dns" || permit.Source != row.Source || permit.Owner != r.Identity.Public || permit.DNS != request.DNS || permit.Spec != control.AppDNSNativeDigest(row) {
		return deployment.ErrInputs
	}
	v, err = r.Engine().ReadAtLeast(ctx, reply.CommandIndex)
	if err != nil {
		return errors.Join(err, deployment.ErrInputs)
	}
	current, actual, err := r.controlPolicy.AppDNSMaterial(v.State, r.commandIdentity().Public, p.Config.Tenant, p.Config.ID, r.Identity.Public)
	want, _ := json.Marshal(p.Config)
	got, _ := json.Marshal(current.Config)
	if err != nil || actual.Source != row.Source || control.AppDNSNativeDigest(actual) != permit.Spec || string(want) != string(got) || current.Bridge != p.Bridge || current.BridgeGeneration != p.BridgeGeneration {
		return deployment.ErrInputs
	}
	return nil
}

func (r *Runtime) openAppDNS() error {
	r.dnsMu.Lock()
	defer r.dnsMu.Unlock()
	if r.dns != nil {
		return nil
	}
	if r.network == nil || r.dnsPath == "" {
		return deployment.ErrInputs
	}
	var err error
	r.dns, err = r.newAppDNSOwner()
	return err
}

func (r *Runtime) newAppDNSOwner() (*services.DNSOwner, error) {
	return services.OpenDNSOwner(r.dnsPath, services.DNSOwnerOptions{Cluster: r.controlPolicy.Cluster, Key: r.Identity.Private, Network: r.network, Workload: r.workload, Workloads: r.physicalWorkloads, MaxViews: 1024, MaxQueries: 4096, MaxConnections: 4096, IdleTimeout: 30 * time.Second, Current: r.currentAppDNS, Permit: r.appDNSPermit})
}

func (r *Runtime) dnsOwner() *services.DNSOwner {
	r.dnsMu.RLock()
	defer r.dnsMu.RUnlock()
	return r.dns
}

func appDNSNativeID(row control.AppDNSOwner) string {
	return fmt.Sprintf("dns/%x", row.Reference)
}

func (r *Runtime) observeAppDNS(ctx context.Context, key string, v cluster.View) (json.RawMessage, error) {
	apps, err := r.controlPolicy.ReadApps(v.State)
	if err != nil {
		return nil, err
	}
	_, rows, known := apps.NetworkDNS(r.Identity.Public)
	if !known {
		return nil, deployment.ErrInputs
	}
	object := v.State.Object(key)
	o := ModuleObservation{Schema: 1, Key: key, Local: v.Local, Revision: object.Revision, Generation: object.Generation, Ready: true, DNS: &DNSObservation{}}
	matched := 0
	for _, row := range rows {
		if row.Source.Key != key || row.Source.Generation != object.Generation || row.Source.Revision != object.Revision {
			continue
		}
		matched++
		if matched == 1 {
			o.NativeID = appDNSNativeID(row)
		} else {
			// A management policy may own several real pool instances. Do not
			// invent one native identity for that aggregate source observation.
			o.NativeID = ""
		}
		owner := r.dnsOwner()
		if owner == nil {
			o.Ready = false
			o.Error = "original DNS owner has not resumed"
			return r.managedObservation(o)
		}
		status, err := owner.Inspect(ctx, row.Config.Tenant, row.Config.ID)
		_, actual, materialErr := r.controlPolicy.AppDNSMaterial(v.State, r.commandIdentity().Public, row.Config.Tenant, row.Config.ID, r.Identity.Public)
		if matched == 1 {
			o.DNS.Desired, o.DNS.Applied, o.DNS.Observed = status.Settings.Desired, status.Settings.Applied, status.Settings.Observed
		} else {
			o.DNS.Desired = min(o.DNS.Desired, status.Settings.Desired)
			o.DNS.Applied = min(o.DNS.Applied, status.Settings.Applied)
			o.DNS.Observed = min(o.DNS.Observed, status.Settings.Observed)
		}
		o.DNS.Queries += status.Queries
		o.DNS.Sockets += status.Sockets
		o.DNS.Stopped = o.DNS.Stopped || status.Stopped
		o.DNS.Failed = o.DNS.Failed || status.Failed
		// These are bounded node-wide failure diagnostics, unlike the scoped
		// query/socket counts. A multi-pool aggregate must not multiply them.
		o.DNS.QueryFailures = max(o.DNS.QueryFailures, status.QueryFailures)
		o.DNS.LastQueryError = status.LastQueryError
		o.Ready = o.Ready && err == nil && materialErr == nil && actual.Reference == row.Reference && row.Config.Enabled && status.Ready && !status.Stopped && !status.Failed && status.Settings.Desired == row.Config.Source && status.Settings.Applied == row.Config.Source && status.Settings.Observed == row.Config.Source
		if err == nil && materialErr == nil && status.Ready && !status.Stopped && !status.Failed && row.Config.Enabled && status.Settings.Desired == row.Config.Source && status.Settings.Applied == row.Config.Source && status.Settings.Observed == row.Config.Source {
			material, _, lookupErr := r.controlPolicy.AppDNSMaterial(v.State, r.Identity.Public, row.Config.Tenant, row.Config.ID)
			if lookupErr == nil {
				if network, found := material.Networks.Network(row.Config.Tenant, row.Config.Network); found {
					for _, pool := range network.Pools {
						if pool.ID == row.Config.Pool {
							o.DNS.Resolvers = append(o.DNS.Resolvers, netip.AddrPortFrom(pool.Gateway, 53).String())
						}
					}
				}
			}
		}
		if err != nil {
			o.Error = err.Error()
		} else if materialErr != nil {
			o.Error = materialErr.Error()
		}
	}
	if matched == 0 {
		return nil, deployment.ErrInputs
	}
	slices.Sort(o.DNS.Resolvers)
	o.DNS.Resolvers = slices.Compact(o.DNS.Resolvers)
	if !o.Ready {
		o.DNS.Resolvers = nil
	}
	return r.managedObservation(o)
}

func (r *Runtime) reconcileAppDNS(ctx context.Context, v cluster.View, apps control.Apps) (bool, error) {
	authority, rows, known := apps.NetworkDNS(r.Identity.Public)
	if !known || len(rows) == 0 {
		return false, nil
	}
	for _, row := range rows {
		if row.Managed != nil {
			ref, exists := authority.ReferenceConsumer(row.Reference)
			if !exists {
				return false, deployment.ErrInputs
			}
			if ref.Closed != nil {
				continue
			}
			if err := r.openAppDNS(); err != nil {
				return false, err
			}
			if !row.Config.Enabled {
				proof, err := r.dnsOwner().Retire(ctx, row.Config.Tenant, row.Config.ID)
				if errors.Is(err, reconcile.ErrPending) {
					// TTL completion on this original instance must not starve
					// another managed server's configuration or app progress.
					continue
				}
				if err != nil || proof == nil {
					return false, errors.Join(err, deployment.ErrInputs)
				}
				report, err := r.controlPolicy.ManagedDNSClosure(v.State, r.commandIdentity().Public, *proof, uint64(time.Now().Unix()))
				if err != nil {
					return false, err
				}
				return true, r.sendNetworkDNSProgress(ctx, report)
			}
			observed := r.dnsOwner().Status(row.Config.Tenant, row.Config.ID)
			if !observed.Ready || observed.Settings.Applied != row.Config.Source {
				if err := r.dnsOwner().Apply(ctx, row.Config.Tenant, row.Config.ID); err != nil {
					return false, err
				}
			}
			observed, err := r.dnsOwner().Inspect(ctx, row.Config.Tenant, row.Config.ID)
			if err != nil {
				return false, err
			}
			if !observed.Ready || observed.Stopped || observed.Failed || observed.Settings.Desired != row.Config.Source || observed.Settings.Applied != row.Config.Source || observed.Settings.Observed != row.Config.Source {
				return false, reconcile.ErrPending
			}
			if err := r.dnsOwner().Collect(row.Config.Tenant, row.Config.ID); err != nil {
				return false, err
			}
			if changed, err := r.managedDNSAddressProgress(ctx, v, authority, row); changed || err != nil {
				return changed, err
			}
			// Readiness stays in the real Settings/socket journal. There is
			// no synthetic app Inventory stage or shared Ready observation.
			continue
		}
		if !row.Config.Enabled {
			continue
		}
		var ownerApp control.AppView
		var ownerStage deployment.StageRecord
		found := false
		for _, app := range apps.Records() {
			i, ok := apps.Inventory(app.Tenant, app.App)
			if !ok {
				continue
			}
			if _, retiring := i.Retirement(); retiring {
				continue
			}
			e, ok := i.Execution()
			if !ok || e.Status() == "Paused" || e.Status() == "Stopping" || e.Status() == "Closed" || e.Status() == "Failed" {
				continue
			}
			stage, ok := e.Stage(row.Source.Key)
			if !ok || stage.Result == nil || stage.Result.Code != state.Applied {
				continue
			}
			ownerApp, ownerStage, found = app, stage, true
			break
		}
		if !found {
			continue
		}
		if err := r.openAppDNS(); err != nil {
			return false, err
		}
		observed := r.dnsOwner().Status(row.Config.Tenant, row.Config.ID)
		if !observed.Ready || observed.Settings.Applied != row.Config.Source {
			if err := r.dnsOwner().Apply(ctx, row.Config.Tenant, row.Config.ID); err != nil {
				return false, err
			}
		}
		observed, err := r.dnsOwner().Inspect(ctx, row.Config.Tenant, row.Config.ID)
		if err != nil {
			return false, err
		}
		if !observed.Ready || observed.Settings.Applied != row.Config.Source || observed.Settings.Observed != row.Config.Source {
			return false, reconcile.ErrPending
		}
		native := appDNSNativeID(row)
		if r.freshAppObservation(ownerStage, native, false) {
			continue
		}
		o, err := r.appObservation(ownerApp, ownerStage, native, false)
		if err != nil {
			return false, err
		}
		o.Pins = uint64(observed.Settings.Users)
		o.Signature = ed25519.Sign(r.Identity.Private, deployment.ObservationBytes(o))
		return true, r.appProgress(ctx, v, ownerApp, "observe", row.Source.Key, &o)
	}
	return false, nil
}

func (r *Runtime) managedDNSAddressProgress(ctx context.Context, v cluster.View, authority services.Authority, row control.AppDNSOwner) (bool, error) {
	consumer, exists := authority.ReferenceConsumer(row.Reference)
	if !exists || consumer.Closed != nil {
		return false, deployment.ErrInputs
	}
	for _, allocation := range authority.AddressBook().Checkpoint().Allocations {
		fence, exists := authority.AddressRetirement(allocation)
		if !exists {
			continue
		}
		required, closed := false, false
		for _, need := range fence.Required {
			required = required || need.Consumer == consumer.ID && need.Generation == consumer.Generation && need.Lifetime == consumer.Lifetime && need.Owner == r.Identity.Public
		}
		for _, proof := range fence.Closures {
			closed = closed || proof.Consumer == consumer.ID && proof.Generation == consumer.Generation && proof.Lifetime == consumer.Lifetime && proof.Target == fence.ID && proof.Epoch == fence.Epoch
		}
		if !required || closed {
			continue
		}
		proof, err := r.dnsOwner().RetireAddress(ctx, row.Config.Tenant, row.Config.ID, fence.ID)
		if errors.Is(err, reconcile.ErrPending) {
			continue
		}
		if err != nil || proof == nil {
			return false, errors.Join(err, deployment.ErrInputs)
		}
		report, err := r.controlPolicy.ManagedDNSClosure(v.State, r.commandIdentity().Public, *proof, uint64(time.Now().Unix()))
		if err != nil {
			return false, err
		}
		return true, r.sendNetworkDNSProgress(ctx, report)
	}
	return false, nil
}

// Native Create/Start needs BOTH the committed execution's DNS Activation and
// the current shared projection's local native view. An earlier empty view's
// observation cannot authorize a task after its exact address was committed.
func (r *Runtime) appTaskDNSReady(ctx context.Context, s state.State, apps control.Apps, key string) error {
	goal, err := deployment.DecodeGoalResources(r.controlPolicy.Cluster, key, s.Object(key))
	if err != nil {
		return err
	}
	members, err := r.controlPolicy.Members(s)
	if err != nil {
		return err
	}
	for _, dependency := range goal.Goal.Dependencies {
		if !strings.HasPrefix(dependency.Key, "network/dns/") {
			continue
		}
		object := s.Object(dependency.Key)
		dnsGoal, err := deployment.DecodeGoalResources(r.controlPolicy.Cluster, dependency.Key, object)
		if err != nil || !object.Present || object.Generation != dependency.Generation || object.Revision != dependency.Revision || !members.OwnsResource(r.commandIdentity().Public, dnsGoal.Goal.Owner) {
			return deployment.ErrInputs
		}
		nativeOwner, local := r.nativeOwner(dnsGoal.Goal.Owner)
		_, rows, known := apps.NetworkDNS(dnsGoal.Goal.Owner)
		if !known || !local || nativeOwner.dnsOwner() == nil {
			return deployment.ErrInputs
		}
		found := false
		for _, row := range rows {
			if row.Source.Key != dependency.Key || row.Source.Generation != dependency.Generation {
				continue
			}
			status, err := nativeOwner.dnsOwner().Inspect(ctx, row.Config.Tenant, row.Config.ID)
			if err != nil || !row.Config.Enabled || !status.Ready || status.Settings.Applied != row.Config.Source || status.Settings.Observed != row.Config.Source {
				return deployment.ErrInputs
			}
			found = true
		}
		if !found {
			return deployment.ErrInputs
		}
	}
	object := s.Object(key)
	required, err := r.controlPolicy.ManagedTaskDNS(s, deployment.ObjectRef{Key: key, Generation: object.Generation, Revision: object.Revision})
	if err != nil {
		return err
	}
	for _, row := range required {
		authority, _, known := apps.NetworkDNS(r.Identity.Public)
		reference, held := authority.ReferenceConsumer(row.Reference)
		members, memberErr := r.controlPolicy.Members(s)
		nativeOwner, local := r.nativeOwner(reference.Local.Owner)
		if !known || !held || memberErr != nil || !members.OwnsResource(r.commandIdentity().Public, reference.Local.Owner) || !local || nativeOwner.dnsOwner() == nil {
			return deployment.ErrInputs
		}
		status, err := nativeOwner.dnsOwner().Inspect(ctx, row.Config.Tenant, row.Config.ID)
		if err != nil || !status.Ready || status.Stopped || status.Failed || status.Settings.Desired != row.Config.Source || status.Settings.Applied != row.Config.Source || status.Settings.Observed != row.Config.Source {
			return deployment.ErrInputs
		}
	}
	return nil
}

func (r *Runtime) retireAppDNS(ctx context.Context, v cluster.View, apps control.Apps, app control.AppView, retirement deployment.RetirementView, target deployment.RetirementTarget) (bool, *services.ReferenceClose, error) {
	_, rows, known := apps.NetworkDNS(r.Identity.Public)
	if !known {
		return false, nil, deployment.ErrInputs
	}
	for _, row := range rows {
		if row.Source.Key != target.Original.Step.Key || row.Source.Generation != target.Original.Result.Generation {
			continue
		}
		if row.Config.Enabled {
			return true, nil, r.retirementProgress(ctx, v, app, retirement, "retire-dns", row.Source.Key, control.AppRetirementProgress{})
		}
		if err := r.openAppDNS(); err != nil {
			return false, nil, err
		}
		proof, err := r.dnsOwner().Retire(ctx, row.Config.Tenant, row.Config.ID)
		if errors.Is(err, reconcile.ErrPending) {
			return true, nil, nil
		}
		return false, proof, err
	}
	return false, nil, deployment.ErrInputs
}

func (r *Runtime) retireNetworkAddresses(ctx context.Context, v cluster.View, apps control.Apps, app control.AppView, retirement deployment.RetirementView, c deployment.Claim) (bool, error) {
	a, _, known := apps.NetworkDNS(r.Identity.Public)
	if !known {
		return false, nil
	}
	allocations, err := apps.NetworkRetirementAllocations(app.Tenant, app.App, c.Step.Key)
	if err != nil {
		return false, err
	}
	var addresses []services.ReferenceRetirement
	waiting := false
	for _, alloc := range allocations {
		// An address is fenced and released only through its closed Task
		// (closedAddressTask in the reducer). While that Task is still being
		// retired, a fence for its address is always rejected; sending it would
		// return here first on every pass and starve the Task's own retirement.
		if !closedAddressTarget(retirement, alloc) {
			waiting = true
			continue
		}
		f, exists := a.AddressRetirement(alloc)
		if !exists {
			return true, r.retirementProgress(ctx, v, app, retirement, "retire-addresses", c.Step.Key, control.AppRetirementProgress{Phase: "fence"})
		}
		if !a.AddressConsumersSettled(alloc) {
			// Hold this original target, allowing the same controller pass to
			// reach managed DNS hot publication/query/TTL collection below.
			return false, reconcile.ErrPending
		}
		addresses = append(addresses, f)
		if len(addresses) == 16 {
			break
		}
	}
	if len(addresses) == 0 {
		if waiting {
			return false, reconcile.ErrPending
		}
		return false, nil
	}
	boot, err := services.NativeBootID()
	if err != nil {
		return false, err
	}
	var proofs []services.AddressOwnerClose
	for _, f := range addresses {
		var task deployment.RetirementTarget
		for _, candidate := range retirement.Targets {
			c := candidate.Original
			if candidate.Closed && c.Step.Kind == "task" && c.Result.Generation == f.Target.Allocation.Generation && strings.HasPrefix(f.Target.Allocation.Endpoint, c.Step.Key+"/") {
				task = candidate
				break
			}
		}
		taskOwner, local := r.nativeOwner(task.Original.Step.Owner)
		members, memberErr := r.controlPolicy.Members(v.State)
		allocationOwner, ownerErr := identity.ParseKey(f.Target.Allocation.Owner)
		nativeOwner, nativeLocal := r.nativeOwner(allocationOwner)
		if task.Drain == nil || task.Drain.Result == nil || taskOwner == nil || !local || taskOwner.workload == nil || memberErr != nil || ownerErr != nil || !nativeLocal || !members.OwnsResource(r.commandIdentity().Public, task.Original.Step.Owner) || !members.OwnsResource(r.commandIdentity().Public, allocationOwner) {
			return false, deployment.ErrInputs
		}
		gone, e := taskOwner.workload.Gone(ctx, task.Original.Step.Key, task.Drain.Result.Revision, task.Original.Result.Generation)
		if e != nil || !gone {
			return false, errors.Join(e, deployment.ErrInputs)
		}
		proof := services.AddressOwnerClose{Cluster: r.controlPolicy.Cluster, Target: f.ID, Epoch: f.Epoch, Owner: allocationOwner, Boot: boot, At: time.Now().Unix(), Native: task.Original.ClosedNative(), Fenced: true, Stopped: true}
		proof.Signature = ed25519.Sign(nativeOwner.Identity.Private, services.AddressOwnerCloseBytes(proof))
		proofs = append(proofs, proof)
	}
	return true, r.retirementProgress(ctx, v, app, retirement, "retire-addresses", c.Step.Key, control.AppRetirementProgress{Phase: "release", Addresses: proofs})
}

func (r *Runtime) appBridgeNetworkClosure(v cluster.View, apps control.Apps, c deployment.Claim) (*tenancy.NetworkClosure, error) {
	a, _, known := apps.NetworkDNS(r.Identity.Public)
	if !known {
		return nil, nil
	}
	g, err := deployment.DecodeGoalResources(r.controlPolicy.Cluster, c.Step.Key, state.Object{Present: true, Value: c.Command.Value, Generation: c.Result.Generation, Revision: c.Result.Revision})
	if err != nil || g.Network == nil {
		return nil, deployment.ErrInputs
	}
	if _, held := a.AddressBook().Pool(g.Goal.Tenant + "/" + g.Network.ID + "/pool"); !held {
		return nil, nil
	}
	p, err := r.controlPolicy.ProjectResources(v.State)
	if err != nil {
		return nil, err
	}
	n, ok := p.Resources.Networks.Network(g.Goal.Tenant, g.Network.ID)
	if !ok || !n.Draining {
		return nil, deployment.ErrInputs
	}
	proof := tenancy.NetworkClosure{Cluster: r.controlPolicy.Cluster, Tenant: n.Tenant, Network: n.ID, Node: n.Node, Owner: n.Owner, Generation: n.Generation, Revision: n.Revision, NativeGone: true}
	proof.Signature = ed25519.Sign(r.Identity.Private, tenancy.NetworkClosureBytes(proof))
	return &proof, nil
}

// closedAddressTarget reports whether alloc belongs to a closed Task target of
// this retirement, the precondition the reducer checks before fencing it.
func closedAddressTarget(retirement deployment.RetirementView, alloc network.Allocation) bool {
	for _, candidate := range retirement.Targets {
		c := candidate.Original
		if candidate.Closed && c.Step.Kind == "task" && c.Result.Generation == alloc.Generation && strings.HasPrefix(alloc.Endpoint, c.Step.Key+"/") {
			return true
		}
	}
	return false
}
