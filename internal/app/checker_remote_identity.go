// SPDX-License-Identifier: Apache-2.0

package app

import (
	"github.com/jay94ks/mydcd/internal/cluster/control"
	"github.com/jay94ks/mydcd/internal/identity"
	"github.com/jay94ks/mydcd/internal/mydcp"
	checker "github.com/jay94ks/mydcd/internal/workload/lifecycle"
)

// Select only the original resource names frozen into the request. Current TLS
// authenticates the callers separately; it cannot rename a Task, native probe,
// run or retained journal. Ambiguous roles never select an arbitrary namespace.
func (r *Runtime) checkerRemoteOriginal(q control.CheckerProbeRequest) (*Runtime, checkerRemoteCall, error) {
	p := checkerRemoteCall{Schema: 1, Query: q, Header: q.HeaderDigest(), Call: (checker.ProbeCall{Binding: checker.ProbeBinding(q.Run.Request), Sequence: q.Sequence}).ID(), Phase: "prepared"}
	consumers, providers := 0, 0
	for _, target := range q.Run.Request.Targets {
		if target.TaskKey == q.Task.Key && target.Generation == q.Task.Generation && target.Revision == q.Task.Revision {
			key, err := identity.ParseKey(target.Owner)
			if err != nil {
				return nil, checkerRemoteCall{}, mydcp.ErrAdmission
			}
			p.Consumer = key
			consumers++
		}
		if target.Service == q.Service {
			key, err := identity.ParseKey(target.Owner)
			if err != nil {
				return nil, checkerRemoteCall{}, mydcp.ErrAdmission
			}
			p.Provider = key
			providers++
		}
	}
	if consumers != 1 || providers != 1 || p.validate(r.controlPolicy.Cluster, p.Provider) != nil {
		return nil, checkerRemoteCall{}, mydcp.ErrAdmission
	}
	owner, ok := r.nativeOwner(p.Provider)
	if !ok || owner.Identity == nil || owner.Identity.Public != p.Provider {
		return nil, checkerRemoteCall{}, mydcp.ErrAdmission
	}
	return owner, p, nil
}
