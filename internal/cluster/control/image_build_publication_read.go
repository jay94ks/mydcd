// SPDX-License-Identifier: Apache-2.0

package control

import (
	"slices"

	"github.com/jay94ks/seafield/internal/access"
	"github.com/jay94ks/seafield/internal/cluster/state"
	"github.com/jay94ks/seafield/internal/registryclient"
)

// This is a read of an accepted job's exact output tag, never a fresh build,
// registry login grant, mutable source lookup or arbitrary repository read.
type ImageBuildPublicationQuery struct {
	Tenant, Job string
	Snapshot    [32]byte
	Target      string
}

type ImageBuildPublicationRead struct {
	Query        ImageBuildPublicationQuery
	Run          RegistryRunRef
	Index, Epoch uint64
}

type ImageBuildPublicationObservation struct {
	Schema uint8
	Read   ImageBuildPublicationRead
	Code   string
	Result *registryclient.Resolution `json:",omitempty"`
}

// SameRegistryReadRun excludes heartbeat readiness and drain flags from this
// read-only identity. It does not weaken writer/dispatch CAS or MayStart.
func SameRegistryReadRun(a, b RegistryRunRef) bool {
	ab, bb := a.Budget, b.Budget
	ab.Revision, bb.Revision = 0, 0
	ab.Draining, bb.Draining = false, false
	return a.Generation == b.Generation && a.SpecRevision == b.SpecRevision && a.Spec == b.Spec && a.Owner == b.Owner && a.Principal == b.Principal && a.DefinitionDigest == b.DefinitionDigest && a.OriginDigest == b.OriginDigest && a.Consumer == b.Consumer && ab == bb
}

func (o ImageBuildPublicationObservation) Valid(q ImageBuildPublicationQuery) bool {
	if o.Schema != 1 || o.Read.Query != q || o.Read.Index == 0 || o.Read.Epoch == 0 || o.Read.Run.Generation == 0 || o.Read.Run.Owner == ([32]byte{}) {
		return false
	}
	if o.Code == "OK" {
		return o.Result != nil && o.Result.Valid(q.Target)
	}
	return (o.Code == "NOT_FOUND" || o.Code == "UNAVAILABLE") && o.Result == nil
}

// Recovery keeps the original accepted user's target, not its current write
// authority. Only the currently installed original builder may ask. Expiry,
// cancellation, user revocation, cordon and policy edits cannot authorize a
// new push, but do not turn an already sent output into an unobservable effect.
func (p Policy) ImageBuildPublicationRead(s state.State, caller [32]byte, q ImageBuildPublicationQuery) (ImageBuildPublicationRead, error) {
	p, err := p.Current(s)
	if err != nil {
		return ImageBuildPublicationRead{}, err
	}
	if !validID(q.Tenant) || !validID(q.Job) || q.Snapshot == ([32]byte{}) {
		return ImageBuildPublicationRead{}, access.ErrInvalid
	}
	book, err := p.ImageBuilds(s)
	if err != nil {
		return ImageBuildPublicationRead{}, err
	}
	job, ok := book.Job(q.Tenant, q.Job)
	if !ok || job.Deleted || job.Run.Phase == "queued" || job.Run.Spec.Digest() != q.Snapshot || job.Run.Spec.Scope.Root.Key != caller {
		return ImageBuildPublicationRead{}, access.ErrDenied
	}
	spec := job.Run.Spec
	owner, err := p.nodeOwner(s, spec.Scope.Root.Node)
	if err != nil || owner != caller {
		return ImageBuildPublicationRead{}, access.ErrDenied
	}
	targets, err := spec.OutputTags()
	if err != nil || !slices.Contains(targets, q.Target) {
		return ImageBuildPublicationRead{}, access.ErrDenied
	}
	registries, err := p.Registries(s)
	if err != nil {
		return ImageBuildPublicationRead{}, err
	}
	entry, ok := registries.Entry(q.Tenant, spec.Policy.Registry)
	if !ok || entry.Active == nil {
		return ImageBuildPublicationRead{}, access.ErrConflict
	}
	run := entry.Active.Reference()
	// An active run may be draining or no longer allowed to start. Read only
	// the exact original specification/data namespace, never a replacement.
	if run.Spec.Tenant != spec.Tenant || run.Spec.ID != spec.Policy.Registry || run.Spec.Authority != spec.RegistryAuthority || run.Spec.Digest() != spec.RegistrySpec {
		return ImageBuildPublicationRead{}, access.ErrConflict
	}
	registryOwner, err := p.nodeOwner(s, run.Spec.Node)
	if err != nil || registryOwner != run.Owner {
		return ImageBuildPublicationRead{}, access.ErrDenied
	}
	return ImageBuildPublicationRead{Query: q, Run: run, Index: s.Index(), Epoch: s.ModuleEpoch()}, nil
}

// Pending original output observation and frozen managed FROM references retain
// the same registry data writer, not a listener or permission for new work.
func (p Policy) RegistryImageBuildsPending(s state.State, run RegistryRunRef) (bool, error) {
	book, err := p.ImageBuilds(s)
	if err != nil {
		return false, err
	}
	digest := run.Spec.Digest()
	for _, job := range book.Jobs {
		spec := job.Run.Spec
		if !job.Run.Terminal() && spec.Tenant == run.Spec.Tenant {
			for _, source := range job.Sources {
				if source.Managed != nil && source.Managed.ID == run.Spec.ID && source.Managed.Generation == run.Generation && source.Managed.Definition == digest && source.Owner == run.Owner {
					return true, nil
				}
			}
		}
		if !job.Deleted && !job.Run.Terminal() && job.Run.Phase != "queued" && spec.Tenant == run.Spec.Tenant && spec.Policy.Registry == run.Spec.ID && spec.RegistryAuthority == run.Spec.Authority && spec.RegistrySpec == digest {
			return true, nil
		}
	}
	return false, nil
}
