// SPDX-License-Identifier: Apache-2.0

package app

import (
	"context"
	"encoding/json"
	"errors"
	"runtime"
	"slices"

	"github.com/jay94ks/seafield/internal/cluster"
	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/schema"
	"github.com/jay94ks/seafield/internal/sfcp"
	"github.com/jay94ks/seafield/internal/storage"
	checker "github.com/jay94ks/seafield/internal/workload/lifecycle"
)

// Node-local availability metadata, never a build/Start grant or Ready. A
// positive missing result is distinct from unavailable authority/DB/transport.
type checkerCacheObservation struct {
	Schema                                  uint8
	Cluster, Provider, Use, Content, Recipe [32]byte
	Index                                   uint64
	Found, CanBuild                         bool
	Fact                                    *checker.CompiledFact `json:",omitempty"`
}

func (r *Runtime) observeCheckerCache(ctx context.Context, caller [32]byte, q control.CheckerArtifactRequest) (checkerCacheObservation, error) {
	if q.Lookup == nil || !r.resourceCaller(ctx, caller, q.Consumer) || !r.acceptsResourceKey(ctx, q.Lookup.Provider) || q.Module != nil || q.Compiled != nil {
		return checkerCacheObservation{}, sfcp.ErrAdmission
	}
	if owner, ok := r.nativeOwner(q.Lookup.Provider); ok && owner != r {
		return owner.observeCheckerCache(ctx, caller, q)
	}
	if q.Lookup.Provider != r.Identity.Public {
		return checkerCacheObservation{}, sfcp.ErrAdmission
	}
	permit, err := r.checkerArtifactPermit(ctx, q)
	if err != nil {
		return checkerCacheObservation{}, err
	}
	r.life.RLock()
	if r.closed || r.ctx.Err() != nil || r.checkerSources == nil {
		r.life.RUnlock()
		return checkerCacheObservation{}, sfcp.ErrAdmission
	}
	fact, data, err := r.checkerSources.CompiledArtifact(ctx, q.Tenant, q.Lookup.Recipe.Key())
	clear(data)
	r.life.RUnlock()
	value := checkerCacheObservation{Schema: 1, Cluster: r.controlPolicy.Cluster, Provider: r.Identity.Public, Use: q.Use, Content: q.Content, Recipe: q.Lookup.Recipe.Key(), Index: permit.Index}
	if err == nil {
		if fact.Owner != r.Identity.Public || fact.Build.Recipe.Key() != q.Lookup.Recipe.Key() {
			return checkerCacheObservation{}, checker.ErrSourceStore
		}
		proof := q
		proof.Lookup = nil
		proof.Compiled = &fact
		// Cache existence without original closed provenance is not a miss
		// and must never trigger another compiler job.
		if _, err = r.checkerArtifactPermit(ctx, proof); err != nil {
			return checkerCacheObservation{}, err
		}
		value.Found, value.Fact = true, &fact
	} else if !errors.Is(err, storage.ErrMissing) || errors.Is(err, checker.ErrSourceStore) {
		return checkerCacheObservation{}, err
	}
	current, err := r.checkerArtifactPermit(ctx, q)
	if err != nil || !current.Equal(permit) {
		return checkerCacheObservation{}, sfcp.ErrAdmission
	}
	value.Index = current.Index
	// Placement hint only. Actual reservation checks current user/image/node
	// authority and native Start checks the original quorum permit again.
	value.CanBuild = !r.historicalOwner && r.checkerCompiler != nil && r.installation != nil && q.Lookup.Recipe.GOOS == runtime.GOOS && q.Lookup.Recipe.GOARCH == runtime.GOARCH && slices.Contains(current.Policy.Build.Nodes, r.installation.record.Root.Self.ID)
	return value, nil
}

func checkerCacheObservationAllowed(v checkerCacheObservation, q control.CheckerArtifactRequest, clusterID [32]byte) error {
	if q.Lookup == nil || q.Module != nil || q.Compiled != nil || clusterID == ([32]byte{}) || q.Schema != 1 || q.MinimumIndex == 0 || q.Consumer == ([32]byte{}) || q.Use == ([32]byte{}) || q.Lookup.Provider == ([32]byte{}) || q.Lookup.Recipe.Validate() != nil || q.Lookup.Recipe.Source != q.Content || q.Lookup.Recipe.Tenant != q.Tenant || v.Schema != 1 || v.Cluster != clusterID || v.Provider != q.Lookup.Provider || v.Use != q.Use || v.Content != q.Content || v.Recipe != q.Lookup.Recipe.Key() || v.Index < q.MinimumIndex || v.Found != (v.Fact != nil) {
		return sfcp.ErrAdmission
	}
	if v.Fact != nil && (v.Fact.Verify() != nil || v.Fact.Owner != v.Provider || v.Fact.Build.Cluster != clusterID || v.Fact.Build.Recipe.Key() != v.Recipe) {
		return sfcp.ErrAdmission
	}
	return nil
}

// One read of one current member. Errors/absence of response are never
// converted to Found=false. Caller owns any subsequent original job decision.
func (r *Runtime) checkerCache(ctx context.Context, q control.CheckerArtifactRequest) (checkerCacheObservation, error) {
	if q.Lookup == nil || q.Module != nil || q.Compiled != nil || q.Consumer != r.Identity.Public || !r.acceptsResourceKey(ctx, q.Consumer) {
		return checkerCacheObservation{}, sfcp.ErrAdmission
	}
	var value checkerCacheObservation
	var err error
	if r.acceptsResourceKey(ctx, q.Lookup.Provider) {
		value, err = r.observeCheckerCache(ctx, r.commandIdentity().Public, q)
	} else {
		peer, ok := r.resourcePeerForKey(ctx, q.Lookup.Provider)
		if !ok || !peer.Member {
			return checkerCacheObservation{}, sfcp.ErrAdmission
		}
		raw, _ := json.Marshal(q)
		var reply cluster.ManagementReply
		reply, err = cluster.CallManagement(ctx, r.Mesh, r.commandIdentity(), r.controlPolicy.Cluster, peer, cluster.ManagementRequest{Method: "checker-cache-observe", Input: raw})
		if err == nil {
			value, err = schema.Decode[checkerCacheObservation](reply.Data)
		}
	}
	if err != nil {
		return checkerCacheObservation{}, err
	}
	if err = checkerCacheObservationAllowed(value, q, r.controlPolicy.Cluster); err != nil {
		return checkerCacheObservation{}, err
	}
	q.MinimumIndex = max(q.MinimumIndex, value.Index)
	if _, err = r.checkerArtifactPermit(ctx, q); err != nil {
		return checkerCacheObservation{}, err
	}
	if value.Fact != nil {
		proof := q
		proof.Lookup = nil
		proof.Compiled = value.Fact
		if _, err = r.checkerArtifactPermit(ctx, proof); err != nil {
			return checkerCacheObservation{}, err
		}
	}
	return value, nil
}
