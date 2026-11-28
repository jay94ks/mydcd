// SPDX-License-Identifier: Apache-2.0

package control

import (
	"encoding/json"
	"net/netip"
	"slices"
	"strconv"
	"strings"

	"github.com/jay94ks/seafield/internal/access"
	"github.com/jay94ks/seafield/internal/cluster/state"
	"github.com/jay94ks/seafield/internal/deployment"
	"github.com/jay94ks/seafield/internal/network/services"
	"github.com/jay94ks/seafield/internal/schema"
	"github.com/jay94ks/seafield/internal/tenancy"
)

// A managed DNS source is the authoritative server policy, not an app Goal,
// a local socket journal, a second network reservation or a Ready observation.
type ManagedDNSSource = services.ManagedDNSSource

func managedDNSPayload(raw []byte) (json.RawMessage, error) {
	canonical, err := normalizedPayload[services.ManagedDNSDefinition](raw)
	if err != nil {
		return nil, err
	}
	var fields struct{ Policy map[string]json.RawMessage }
	if json.Unmarshal(raw, &fields) != nil {
		return nil, schema.ErrInput
	}
	// This is a full explicit policy replacement. In particular an omitted
	// false/zero/empty field must not silently disable an existing server,
	// clear its upstream list or discard its cache policy.
	for _, key := range []string{"Enabled", "Upstreams", "MaxCacheEntries"} {
		value := fields.Policy[key]
		if len(value) == 0 || string(value) == "null" {
			return nil, schema.ErrInput
		}
	}
	return canonical, nil
}

// ManagedDNS reads the same committed source rows, retaining policy even when
// its original principal loses permission. Current admission is checked by the
// consuming owner; revocation must not turn persisted policy into missing data.
func (p Policy) ManagedDNS(s state.State) (map[string]ManagedDNSSource, error) {
	out := map[string]ManagedDNSSource{}
	for key, object := range s.Objects(services.ManagedDNSPrefix) {
		if !object.Present {
			continue
		}
		var source ManagedDNSSource
		if object.Generation == 0 || object.Revision < object.Generation || canonical([]byte(object.Value), &source) != nil || source.Schema != 1 || source.Cluster != p.Cluster || !validID(source.Principal) || source.Definition.Schema != 1 || services.ManagedDNSKey(source.Definition.Tenant, source.Definition.Network) != key {
			return nil, ErrCatalog
		}
		out[key] = source
	}
	return out, nil
}

func (p Policy) configureManagedDNS(s state.State, op UserOperation) (map[string][]byte, error) {
	var definition services.ManagedDNSDefinition
	if canonical(op.Change.Payload, &definition) != nil || definition.Schema != 1 || definition.Policy.Upstreams == nil {
		return nil, ErrCatalog
	}
	key := services.ManagedDNSKey(definition.Tenant, definition.Network)
	object := s.Object(key)
	if key == "" || object.Revision != op.Change.Expected {
		return nil, ErrCatalog
	}
	if definition.RetainReserved && (definition.Policy.Enabled || !object.Present) {
		return nil, ErrCatalog
	}
	sources, err := p.ManagedDNS(s)
	if err != nil {
		return nil, err
	}
	if old, exists := sources[key]; object.Present && (!exists || old.Definition.Tenant != definition.Tenant || old.Definition.Network != definition.Network) {
		return nil, ErrCatalog
	}
	if old, exists := sources[key]; exists {
		originalApps, err := p.Apps(s)
		if err != nil {
			return nil, err
		}
		closing := false
		if originalApps.network != nil {
			for _, group := range originalApps.network.Groups {
				if group.Managed && !managedDNSGroupEnabled(group) {
					for _, owner := range group.Owners {
						closing = closing || owner.Source.Key == key
					}
				}
			}
		}
		if !old.Definition.Policy.Enabled || closing {
			apps, err := p.Apps(s)
			if err != nil {
				return nil, err
			}
			// Disable is a one-way native retirement until every ORIGINAL owner
			// positively closes its instance. Re-enabling the same lifetime would
			// conflict with its permanent local fence. A second disabled policy
			// also must not replace the exact input under an in-flight Stop/Wait.
			if managedDNSLiveReferences(apps, key) {
				return nil, ErrCatalog
			}
		}
	}
	projection, err := p.ProjectResources(s)
	if err != nil || !projection.Compatible {
		return nil, ErrCatalog
	}
	catalog, err := p.Catalog(s)
	if err != nil {
		return nil, err
	}
	// A read-only validation view over the exact existing reservation book.
	// No new address/Authority checkpoint or DNS instance grant is persisted.
	authority, err := projection.addressAuthority(p.Cluster)
	if err != nil {
		return nil, err
	}
	registrations, err := p.managedDNSRegistrations(s, projection, definition, nil)
	if err != nil {
		return nil, err
	}
	if !definition.RetainReserved {
		_, err = definition.Plans(catalog, projection.Resources.Networks, authority, op.Change.Principal, 1, 1, registrations)
	} else {
		// Disabling retains the original members under their already reserved
		// network change. It allocates no replacement/native serving instance.
		_, err = definition.RetainedPlans(catalog, projection.Resources.Networks, authority, op.Change.Principal, 1, 1, registrations)
	}
	if err != nil {
		return nil, err
	}
	if definition.Policy.Enabled {
		members, err := p.Members(s)
		if err != nil {
			return nil, err
		}
		for _, network := range projection.Resources.Networks.AllNetworks() {
			if network.Tenant == definition.Tenant && network.Logical == definition.Network && !members.WorkKey(p.currentResourceKey(s, network.Owner, true)) {
				return nil, access.ErrDenied
			}
		}
		apps, err := p.Apps(s)
		if err != nil {
			return nil, err
		}
		sources[key] = ManagedDNSSource{Schema: 1, Cluster: p.Cluster, Principal: op.Change.Principal, Definition: definition}
		projection.ManagedDNSConsumers = managedDNSConsumerDemand(projection, apps, sources)
		if err := admitManagedDNSConsumers(projection, definition); err != nil {
			return nil, err
		}
	}
	raw, err := json.Marshal(ManagedDNSSource{Schema: 1, Cluster: p.Cluster, Principal: op.Change.Principal, Definition: definition})
	if err != nil {
		return nil, err
	}
	return map[string][]byte{key: raw}, nil
}

func managedDNSLiveReferences(apps Apps, key string) bool {
	if apps.network == nil {
		return false
	}
	for _, group := range apps.network.Groups {
		if !group.Managed {
			continue
		}
		for _, row := range group.Owners {
			if row.Source.Key != key {
				continue
			}
			ref, exists := apps.network.Authority.ReferenceConsumer(row.Reference)
			if !exists || ref.Closed == nil {
				return true
			}
		}
	}
	return false
}

// Names are derived from Inventory's original accepted commands/results and
// the SAME projected address reservations. No registration table is copied
// beside Tasks, and arbitrary native-looking metadata gains no DNS ownership.
func (p Policy) managedDNSRegistrations(s state.State, projection ResourceProjection, definition services.ManagedDNSDefinition, current *state.Command) ([]services.DNSRegistration, error) {
	apps, err := p.Apps(s)
	if err != nil {
		return nil, err
	}
	return p.managedDNSRegistrationsFromApps(s, apps, projection, definition, current)
}

// Callers pass Apps already checked against this same immutable state. Task
// receipts, object identity and current mutations are still checked below.
func (p Policy) managedDNSRegistrationsFromApps(s state.State, apps Apps, projection ResourceProjection, definition services.ManagedDNSDefinition, current *state.Command) ([]services.DNSRegistration, error) {
	accepted := map[string]state.Command{}
	accept := func(command *state.Command, result *state.Result) {
		if command == nil {
			return
		}
		o := s.Object(command.Key)
		if result == nil {
			if receipt, found := s.LookupResult(*command); found {
				// An actual commit precedes the owner's app-stage collect report.
				// Its names already compete with the next Task transaction.
				result = &receipt
			} else if current != nil && *current == *command && command.Kind == state.Mutate && !command.Delete && o.Present && o.Value == command.Value && o.Revision == s.Index() {
				// Only validateManagedTaskDNS passes this exact current mutation,
				// AFTER validateAppCommands checks its original bound dispatch.
				result = &state.Result{Code: state.Applied, Index: s.Index(), Generation: o.Generation, Revision: o.Revision}
			}
		}
		if result == nil || result.Code != state.Applied {
			return
		}
		if o.Present && o.Value == command.Value && o.Generation == result.Generation && o.Revision == result.Revision {
			accepted[command.Key] = *command
		}
	}
	for _, entry := range apps.entries {
		for _, claim := range entry.Inventory.Claims() {
			if !claim.Removed && claim.Step.Kind == "task" {
				accept(&claim.Command, &claim.Result)
			}
		}
		if execution, active := entry.Inventory.Execution(); active {
			for _, step := range execution.Steps() {
				if step.Kind != "task" {
					continue
				}
				stage, found := execution.Stage(step.Key)
				if found {
					accept(stage.Command, stage.Result)
				}
			}
		}
	}
	keys := make([]string, 0, len(accepted))
	for key := range accepted {
		keys = append(keys, key)
	}
	slices.Sort(keys)
	objects := s.Objects("")
	var out []services.DNSRegistration
	for _, key := range keys {
		row, found := projection.Goals[key]
		g := row.Goal
		if !found || g.Kind != "task" || g.Tenant != definition.Tenant || g.Lifecycle != nil && g.Lifecycle.Drain {
			continue
		}
		var service deployment.ComposeService
		if canonical(g.Config, &service) != nil {
			return nil, ErrCatalog
		}
		for alias, attachment := range service.Networks {
			material, err := deployment.ResolveTaskNetwork(p.Cluster, g, alias, objects)
			if err != nil {
				return nil, err
			}
			if material.Reference == nil || material.Reference.ManagedName != definition.Network {
				continue
			}
			instance, err := deployment.TaskInstanceForKey(g.Tenant, g.App, key, service)
			if err != nil || instance.Node != g.Node {
				return nil, ErrCatalog
			}
			registration := services.DNSRegistration{Tenant: g.Tenant, Network: definition.Network, App: g.App, Service: instance.Service, Aliases: slices.Clone(attachment.Aliases)}
			if service.Standalone && definition.Policy.Enabled && len(registration.Aliases) == 0 {
				name, err := standaloneTaskDNSName(s, apps, g, accepted[key])
				if err != nil {
					return nil, err
				}
				registration.Aliases = []string{name}
			}
			if instance.Ordinal != 0 {
				registration.Task = key
			}
			for family, raw := range []string{attachment.IPv4, attachment.IPv6} {
				if raw == "" {
					continue
				}
				endpoint := key + "/" + alias + "/" + strconv.Itoa(family)
				allocation, held := projection.Addresses.AllocationOf(endpoint, s.Object(key).Generation)
				address, err := netip.ParseAddr(raw)
				if err != nil || !held || allocation.Generation != s.Object(key).Generation || allocation.Address != address {
					return nil, ErrCatalog
				}
				registration.Addresses = append(registration.Addresses, services.DNSAddressReference{Endpoint: endpoint, Generation: allocation.Generation})
			}
			out = append(out, registration)
		}
	}
	return out, nil
}

// The default belongs to the ORIGINAL accepted Task, rather than its mutable
// public pin name. Read it only while projecting a DNS-enabled managed network;
// putting an alias in the raw attachment would incorrectly require managed DNS
// for otherwise valid standalone connections to networks without DNS.
//
// Bindings preserve the signed original acceptance across pin and later Keep
// operations. Before the first binding exists, the exact active non-noop Task
// command supplies that same provenance, including the commit/collect gap used
// by name collision admission. No independent name registration is persisted.
func standaloneTaskDNSName(s state.State, apps Apps, g deployment.GoalCommand, command state.Command) (string, error) {
	entry, exists := apps.entries[appKey(g.Tenant, g.App)]
	_, keyErr := deployment.ResourceIDFromKey("task", g.Tenant, g.App, command.Key)
	if !exists || entry.Standalone == nil || g.Kind != "task" || keyErr != nil {
		return "", ErrCatalog
	}
	object := s.Object(command.Key)
	if !object.Present || object.Value != command.Value {
		return "", ErrCatalog
	}
	task := deployment.ObjectRef{Key: command.Key, Generation: object.Generation, Revision: object.Revision}
	original := func(origin UserOperation) (string, error) {
		var begin AppBegin
		if origin.VerifyOriginal(g.Cluster) != nil || origin.Change.Action != "standalone-up" || canonical(origin.Change.Payload, &begin) != nil || begin.Standalone == nil || begin.Tenant != g.Tenant || begin.App != g.App || begin.Deployment != g.Deployment || deployment.StandaloneScopeName(g.Tenant, begin.Standalone.Name) == "" {
			return "", ErrCatalog
		}
		return begin.Standalone.Name, nil
	}
	for _, source := range apps.sources {
		if source.Task == task {
			if source.Command != state.Digest(command) {
				return "", ErrCatalog
			}
			return original(source.Origin)
		}
	}
	if execution, active := entry.Inventory.Execution(); active {
		if stage, found := execution.Stage(command.Key); found && !stage.Noop && stage.Command != nil && *stage.Command == command {
			return original(entry.Origin)
		}
	}
	return "", ErrCatalog
}

func managedSourceKey(key string) bool {
	return strings.HasPrefix(key, services.ManagedDNSPrefix) || strings.HasPrefix(key, tenancy.ManagedNetworkSourcePrefix)
}
