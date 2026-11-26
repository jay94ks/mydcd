// SPDX-License-Identifier: Apache-2.0

package control

import (
	"slices"

	"github.com/jay94ks/mydcd/internal/cluster/state"
	"github.com/jay94ks/mydcd/internal/schema"
)

// ValidateManaged keeps the application FSM independent of local native flags.
// Managed users/members never obtain the old bootstrap native/admin mutation API.
func (p Policy) ValidateManaged(before, after state.State, cmd state.Command) error {
	_, err := p.ValidateManagedStage(before, after, cmd)
	return err
}

// ValidateManagedStage is ValidateManaged naming the refusing check, as
// ValidateStage does. Local diagnostics only; same verdict.
func (p Policy) ValidateManagedStage(before, after state.State, cmd state.Command) (string, error) {
	if stage, err := p.ValidateStage(before, after, cmd); err != nil {
		return stage, err
	}
	if cmd.Actor != "" && (cmd.Kind == state.SetRights || cmd.Kind == state.RotateLedger || cmd.Kind == state.Mutate && !p.AdmitAppMutation(before, cmd)) {
		return "managed", ErrCatalog
	}
	return "", nil
}
func (a Apps) Records() []AppView {
	keys := make([]string, 0, len(a.entries))
	for k := range a.entries {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	var out []AppView
	for _, k := range keys {
		i := a.entries[k].Inventory
		scope := i.Scope()
		out = append(out, appView(a.entries[k], scope))
	}
	return out
}
func (p Policy) ResolveAppCommand(s state.State, method string, caller [32]byte, raw []byte) (state.Command, error) {
	members, err := p.Members(s)
	if err != nil || !members.MemberKey(caller) {
		return state.Command{}, ErrCatalog
	}
	if method == "standalone-policy-report" {
		var q StandalonePolicyReport
		if canonical(raw, &q) != nil || q.Reporter != caller {
			return state.Command{}, ErrCatalog
		}
		cmd, err := q.Command()
		if err != nil {
			return cmd, err
		}
		_, err = p.standalonePolicyReport(s, cmd)
		return cmd, err
	}

	if method == "task-restart-report" {
		r, err := schema.Decode[TaskRestartReport](raw)
		if err != nil || r.Reporter != caller {
			return state.Command{}, ErrCatalog
		}
		cmd, err := r.Command()
		if err != nil {
			return cmd, err
		}
		_, err = p.taskRestartReport(s, cmd)
		return cmd, err
	}
	if method == "app-delivery-progress" {
		report, err := schema.Decode[AppDeliveryProgress](raw)
		if err != nil || report.Reporter != caller {
			return state.Command{}, ErrCatalog
		}
		cmd, err := report.Command()
		if err != nil {
			return cmd, err
		}
		_, err = p.appDeliveryProgress(s, cmd)
		return cmd, err
	}
	if method == "route-retirement" {
		report, err := schema.Decode[RouteRetirementReport](raw)
		if err != nil || report.Reporter != caller {
			return state.Command{}, ErrCatalog
		}
		command, err := report.Command()
		if err != nil {
			return command, err
		}
		_, err = p.routeRetirementReport(s, command)
		return command, err
	}
	if method == "route-dispatch" {
		r, err := schema.Decode[RouteDispatchReport](raw)
		if err != nil || r.Reporter != caller {
			return state.Command{}, ErrCatalog
		}
		cmd, err := r.Command()
		if err != nil {
			return cmd, err
		}
		_, err = p.routeDispatchReport(s, cmd)
		return cmd, err
	}
	if method == "network-dns-progress" {
		r, err := schema.Decode[NetworkDNSProgress](raw)
		if err != nil || r.Reporter != caller {
			return state.Command{}, ErrCatalog
		}
		cmd, err := r.Command()
		if err != nil {
			return cmd, err
		}
		_, err = p.networkDNSProgress(s, cmd)
		return cmd, err
	}
	if method == "app-progress" {
		r, err := schema.Decode[AppProgress](raw)
		if err != nil || r.Reporter != caller {
			return state.Command{}, ErrCatalog
		}
		cmd, err := r.Command()
		if err != nil {
			return cmd, err
		}
		_, err = p.appProgress(s, cmd)
		return cmd, err
	}
	if method == "app-command" {
		cmd, err := state.DecodeCommand(raw)
		if err != nil {
			return cmd, err
		}
		if !p.AdmitAppMutation(s, cmd) {
			return cmd, ErrCatalog
		}
		return cmd, nil
	}
	return state.Command{}, ErrCatalog
}

type AppResult struct {
	Found  bool
	Result *state.Result `json:",omitempty"`
}

func (p Policy) AppResult(s state.State, caller [32]byte, cmd state.Command) (AppResult, error) {
	members, err := p.Members(s)
	if err != nil || !members.MemberKey(caller) {
		return AppResult{}, ErrCatalog
	}
	a, err := p.Apps(s)
	if err != nil {
		return AppResult{}, err
	}
	for _, entry := range a.entries {
		if result, known := appRemovalResult(entry, cmd); known {
			if actual, found := s.LookupResult(cmd); found {
				if result != nil && actual != *result {
					return AppResult{}, ErrCatalog
				}
				return AppResult{true, &actual}, nil
			}
			if result != nil {
				copy := *result
				return AppResult{true, &copy}, nil
			}
			return AppResult{}, nil
		}
		e, ok := entry.Inventory.Execution()
		if !ok {
			continue
		}
		stage, ok := e.Stage(cmd.Key)
		if ok && stage.Command != nil && *stage.Command == cmd {
			result, found := s.LookupResult(cmd)
			if found {
				return AppResult{true, &result}, nil
			}
			if stage.Result != nil {
				r := *stage.Result
				return AppResult{true, &r}, nil
			}
			return AppResult{}, nil
		}
		for _, claim := range entry.Inventory.Claims() {
			if claim.Command == cmd {
				r := claim.Result
				return AppResult{true, &r}, nil
			}
		}
	}
	return AppResult{}, ErrCatalog
}
