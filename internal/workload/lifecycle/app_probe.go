// SPDX-License-Identifier: Apache-2.0

package lifecycle

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"slices"

	contract "github.com/jay94ks/mydcd/lifecycle/v1"
)

// AppCheckServices is the accepted app check's exact service set. The
// coordinator is always bound; scripts can only use their original app set.
func (p TaskProgram) AppCheckServices(check ResolvedCheck) []string {
	services := []string{p.Coordinator}
	if check.Script != "" {
		services = append(services, p.Services...)
	} else if b := check.Builtin; b != nil {
		switch b.Kind {
		case "healthz":
			if b.HTTP != nil {
				services = append(services, b.HTTP.Service)
			}
		case "file":
			if b.File != nil {
				services = append(services, b.File.Service)
			}
		case "cmd":
			if b.Exec != nil {
				services = append(services, b.Exec.Service)
			}
		case "depends_on":
			if b.Dependency != nil {
				services = append(services, b.Dependency.Services...)
			}
		}
	}
	slices.Sort(services)
	return slices.Compact(services)
}

// CheckSourceDigest is shared by the node's Definition and authorization.
// The builtin digest identifies the accepted typed check, not an executable.
func (p TaskProgram) CheckSourceDigest(check ResolvedCheck) ([32]byte, error) {
	if check.Script != "" {
		fact, ok := p.Sources[check.Script]
		if !ok {
			return [32]byte{}, ErrReference
		}
		return fact.ContentDigest(), nil
	}
	if check.Builtin == nil {
		return [32]byte{}, ErrContract
	}
	raw, err := json.Marshal(check.Builtin)
	if err != nil {
		return [32]byte{}, ErrContract
	}
	return sha256.Sum256(raw), nil
}

// AppProbeDefinition reconstructs only an accepted app-scope Definition and
// validates the original dispatched run using the actual Machine core. Task,
// shared native facts and current permission remain the control policy's job.
func (p TaskProgram) AppProbeDefinition(run Run, stop *ShutdownScope) (Definition, ResolvedCheck, error) {
	var empty Definition
	var check ResolvedCheck
	if p.Validate(p.Cluster) != nil || p.Service != p.Coordinator || run.Phase != Dispatched || ValidateRequest(run.Request) != nil || run.Request.Cluster != hex.EncodeToString(p.Cluster[:]) || run.Request.Tenant != p.Tenant {
		return empty, check, ErrContract
	}
	p = p.Clone() // the returned check cannot mutate the accepted TaskProgram
	found := false
	for _, candidate := range p.AppChecks {
		if candidate.ID == run.Request.Checker && candidate.Phase == run.Request.Phase {
			check = candidate
			found = true
			break
		}
	}
	if !found {
		return empty, check, ErrReference
	}
	want, err := p.CheckSourceDigest(check)
	if err != nil || run.Request.SourceDigest != hex.EncodeToString(want[:]) {
		return empty, check, ErrReference
	}
	parameters, _ := json.Marshal(check.Parameters)
	actual, _ := json.Marshal(run.Request.Parameters)
	if !bytes.Equal(parameters, actual) {
		return empty, check, ErrContract
	}
	if (run.Request.Phase == contract.Shutdown) != (stop != nil) {
		return empty, check, ErrContract
	}
	services := p.AppCheckServices(check)
	if len(services) != len(run.Request.Targets) {
		return empty, check, ErrReference
	}
	for i, target := range run.Request.Targets {
		if target.Service != services[i] {
			return empty, check, ErrReference
		}
	}
	request := ownRequest(run.Request)
	request.RunID, request.DeadlineUnixMilli = "", 0
	d := Definition{ProgramDigest: hex.EncodeToString(p.Program[:]), Request: request, Timing: check.Timing, PolicyRevision: p.Policy.Revision}
	if stop != nil {
		value := *stop
		d.Stop = &value
	}
	if d.Validate() != nil || ValidateRun(d, run) != nil {
		return empty, check, ErrContract
	}
	return d, check, nil
}

// ValidateAppProbeCall is used by the remote receiver before any native IO.
// Scripts retain typed capabilities; a builtin may only issue its own exact
// typed query. Hashing a different payload must not widen that declaration.
func (p TaskProgram) ValidateAppProbeCall(run Run, stop *ShutdownScope, current TenantPolicy, call ProbeCall) (ProbeCall, error) {
	_, check, err := p.AppProbeDefinition(run, stop)
	if err != nil {
		return ProbeCall{}, err
	}
	normal, err := NormalizeProbeCall(run.Request, p.Policy, call)
	if err != nil {
		return ProbeCall{}, err
	}
	normal, err = NormalizeProbeCall(run.Request, current, normal)
	if err != nil {
		return ProbeCall{}, err
	}
	if check.Script != "" {
		return normal, nil
	}
	var expected ProbeCall
	expected.Schema, expected.Binding, expected.Sequence, expected.DeadlineUnixMilli = call.Schema, call.Binding, call.Sequence, call.DeadlineUnixMilli
	b := check.Builtin
	switch b.Kind {
	case "healthz":
		expected.Kind, expected.HTTP = "healthz", b.HTTP
	case "cmd":
		expected.Kind, expected.Exec = "exec", b.Exec
	case "file":
		if b.File == nil {
			return ProbeCall{}, ErrContract
		}
		query := &contract.FileProbe{Service: b.File.Service, Path: b.File.Path, Kind: b.File.Kind, ContentDigest: b.File.ContentDigest}
		if query.ContentDigest != "" {
			query.MaxBytes = min(p.Policy.Execution.ProbeBytes, current.Execution.ProbeBytes)
		}
		expected.Kind, expected.File = "file", query
	default:
		return ProbeCall{}, ErrContract
	}
	expected, err = NormalizeProbeCall(run.Request, p.Policy, expected)
	if err != nil {
		return ProbeCall{}, err
	}
	expected, err = NormalizeProbeCall(run.Request, current, expected)
	if err != nil || normal.Digest() != expected.Digest() {
		return ProbeCall{}, ErrContract
	}
	return normal, nil
}
