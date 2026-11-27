// SPDX-License-Identifier: Apache-2.0

package control

import (
	"encoding/json"
	"strings"

	"github.com/jay94ks/seafield/internal/cluster/state"
	"github.com/jay94ks/seafield/internal/deployment"
	"github.com/jay94ks/seafield/internal/network/services"
)

// AppDNSUnavailable filters answers for explicit replicas without releasing
// their committed names, IPAM reservations or retirement references. now is
// supplied by the serving adapter; it is never used in an FSM state transition.
func (p Policy) AppDNSUnavailable(s state.State, config services.DNSConfig, now uint64) ([]services.DNSAddressReference, error) {
	if now == 0 {
		return nil, ErrCatalog
	}
	apps, err := p.readOnlyApps(s)
	if err != nil {
		return nil, err
	}
	members, err := p.Members(s)
	if err != nil {
		return nil, err
	}
	byApp := map[string]map[string]taskProjection{}
	seen := map[services.DNSAddressReference]bool{}
	var unavailable []services.DNSAddressReference
	for _, name := range config.Names {
		parts := strings.Split(name.Endpoint, "/")
		// endpoint = workload/task/tenant/app/service/node/rN/alias/family.
		// Existing singleton/legacy DNS keeps its established publication rule.
		if len(parts) != 9 || parts[0] != "workload" || parts[1] != "task" || parts[2] != config.Tenant {
			continue
		}
		key := strings.Join(parts[:7], "/")
		app := parts[3]
		rows, loaded := byApp[app]
		if !loaded {
			rows = map[string]taskProjection{}
			if entry, exists := apps.entries[appKey(config.Tenant, app)]; exists {
				candidates, err := acceptedTaskCandidates(s, apps, entry.Inventory.Scope(), entry.Inventory.Claims())
				if err != nil {
					return nil, err
				}
				for _, row := range candidates {
					rows[row.ref.Key] = row
				}
			}
			byApp[app] = rows
		}
		row, exists := rows[key]
		var service deployment.ComposeService
		available := false
		if exists && json.Unmarshal(row.goal.Config, &service) == nil {
			instance, identityErr := deployment.TaskInstanceForKey(config.Tenant, app, key, service)
			available = identityErr == nil && instance.Ordinal != 0 && instance.Node == row.goal.Node && row.ref.Generation == name.Generation && taskCandidateAvailable(s, row, now, members.WorkKey(p.currentResourceKey(s, row.goal.Owner, true)))
		}
		ref := services.DNSAddressReference{Endpoint: name.Endpoint, Generation: name.Generation}
		if !available && !seen[ref] {
			unavailable = append(unavailable, ref)
			seen[ref] = true
		}
	}
	return unavailable, nil
}

func taskCandidateAvailable(s state.State, row taskProjection, now uint64, eligible bool) bool {
	current, o := s.Object(row.ref.Key), row.observation
	return eligible && current.Present && current.Generation == row.ref.Generation && current.Revision == row.ref.Revision && o != nil && row.native != "" && o.Native == row.native && o.Owner == row.goal.Owner && o.Generation == row.ref.Generation && o.Revision == row.ref.Revision && o.AvailableAt(now)
}

// The app health label uses the same serving evidence as DNS, including current
// member isolation. One live instance cannot turn an unavailable peer Healthy.
func (p Policy) ObserveAppReplicaHealth(s state.State, apps Apps, row *AppView, now uint64) error {
	entry, exists := apps.entries[appKey(row.Tenant, row.App)]
	e, active := entry.Inventory.Execution()
	if !exists || !active || e.Status() == "Stopping" || e.Status() == "Closed" {
		return nil
	}
	members, err := p.Members(s)
	if err != nil {
		return err
	}
	candidates, err := acceptedTaskCandidates(s, apps, entry.Inventory.Scope(), entry.Inventory.Claims())
	if err != nil {
		return err
	}
	byKey := map[string]taskProjection{}
	for _, candidate := range candidates {
		byKey[candidate.ref.Key] = candidate
	}
	type count struct{ total, available int }
	groups := map[string]count{}
	for _, step := range e.Steps() {
		if step.Kind != "task" {
			continue
		}
		var service deployment.ComposeService
		if json.Unmarshal(step.Goal, &service) != nil || service.Sfc.Instance == nil {
			continue
		}
		name := service.Sfc.Instance.Service
		group := groups[name]
		group.total++
		if candidate, exists := byKey[step.Key]; exists && taskCandidateAvailable(s, candidate, now, members.WorkKey(p.currentResourceKey(s, candidate.goal.Owner, true))) {
			group.available++
		}
		groups[name] = group
	}
	for _, group := range groups {
		if group.available > 0 && group.available < group.total {
			row.Health = "Degraded"
			return nil
		}
		if group.available == 0 && row.Health == "Healthy" {
			row.Health = "Unknown"
		}
	}
	return nil
}
