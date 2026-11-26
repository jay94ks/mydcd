// SPDX-License-Identifier: Apache-2.0

package app

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/jay94ks/mydcd/internal/cluster/control"
	"github.com/jay94ks/mydcd/internal/deployment"
	"github.com/jay94ks/mydcd/internal/mydcp"
	"github.com/jay94ks/mydcd/internal/schema"
	"github.com/jay94ks/mydcd/internal/storage"
	checker "github.com/jay94ks/mydcd/internal/workload/lifecycle"
)

type checkerArtifactMetadata struct {
	Schema   uint8
	Source   *checker.SourceFact   `json:",omitempty"`
	Module   *checker.ModuleFact   `json:",omitempty"`
	Compiled *checker.CompiledFact `json:",omitempty"`
}

func (r *Runtime) checkerArtifactPermit(ctx context.Context, q control.CheckerArtifactRequest) (control.CheckerArtifactPermit, error) {
	q.At = time.Now().Unix()
	raw, _ := json.Marshal(q)
	reply, err := r.appCall(ctx, "checker-artifact-permit", raw)
	if err != nil {
		return control.CheckerArtifactPermit{}, err
	}
	p, err := schema.Decode[control.CheckerArtifactPermit](reply.Data)
	if err != nil || p.Schema != 1 || p.Use != q.Use || p.UseID != q.UseID || p.Tenant != q.Tenant || p.Consumer != q.Consumer || p.Parent == ([32]byte{}) || p.Index < q.MinimumIndex || p.Source.Verify() != nil || p.Source.Cluster != r.controlPolicy.Cluster || p.Source.Tenant != q.Tenant || p.Source.ContentDigest() != q.Content || !p.Policy.AllowsSource(p.Source) {
		return control.CheckerArtifactPermit{}, mydcp.ErrAdmission
	}
	if (p.Compiled == nil) != (q.Compiled == nil) || q.Compiled != nil && (q.Module != nil || p.Compiled.Verify() != nil || p.Compiled.Digest() != q.Compiled.Digest() || p.Compiled.Build.Cluster != p.Source.Cluster || p.Compiled.Build.Recipe.Tenant != q.Tenant || p.Compiled.Build.Recipe.Source != q.Content) {
		return control.CheckerArtifactPermit{}, mydcp.ErrAdmission
	}
	if (p.Lookup == nil) != (q.Lookup == nil) || q.Lookup != nil && (q.Module != nil || q.Compiled != nil || p.Lookup.Provider != q.Lookup.Provider || p.Lookup.Recipe.Validate() != nil || p.Lookup.Recipe.Key() != q.Lookup.Recipe.Key() || p.Lookup.Recipe.Source != q.Content || p.Lookup.Recipe.Tenant != q.Tenant) {
		return control.CheckerArtifactPermit{}, mydcp.ErrAdmission
	}
	return p, nil
}

func checkerArtifactBytes(q control.CheckerArtifactRequest, p control.CheckerArtifactPermit) ([32]byte, uint64) {
	if p.Compiled != nil {
		return p.Compiled.Build.Digest, p.Compiled.Build.Length
	}
	if q.Module != nil {
		return q.Module.Digest, q.Module.Length
	}
	return p.Source.Digest, p.Source.Length
}

func checkerArtifactMetadataAllowed(raw []byte, q control.CheckerArtifactRequest, permit control.CheckerArtifactPermit) error {
	if q.Lookup != nil {
		return mydcp.ErrAdmission
	}
	meta, err := schema.Decode[checkerArtifactMetadata](raw)
	if err != nil || meta.Schema != 1 {
		return mydcp.ErrAdmission
	}
	if q.Compiled != nil {
		if q.Module != nil || permit.Compiled == nil || meta.Source != nil || meta.Module != nil || meta.Compiled == nil || meta.Compiled.Verify() != nil || meta.Compiled.Digest() != permit.Compiled.Digest() {
			return mydcp.ErrAdmission
		}
	} else if q.Module == nil {
		if meta.Compiled != nil || meta.Module != nil || meta.Source == nil || meta.Source.Verify() != nil || meta.Source.Owner != permit.Source.Owner || meta.Source.Cluster != permit.Source.Cluster || meta.Source.Tenant != permit.Tenant || meta.Source.ContentDigest() != q.Content {
			return mydcp.ErrAdmission
		}
	} else {
		if meta.Compiled != nil || meta.Source != nil || meta.Module == nil || meta.Module.Verify() != nil || meta.Module.Owner != permit.Source.Owner || meta.Module.Cluster != permit.Source.Cluster || meta.Module.Tenant != permit.Tenant || meta.Module.Module != *q.Module {
			return mydcp.ErrAdmission
		}
	}
	return nil
}

func (r *Runtime) serveCheckerArtifacts() error {
	return r.Mesh.OnCheckerArtifact(func(ctx context.Context, s *mydcp.Session, wire mydcp.CheckerArtifactRequest) (mydcp.CheckerArtifactSource, error) {
		q, err := schema.Decode[control.CheckerArtifactRequest](wire.Metadata)
		if err != nil || q.Lookup != nil || !r.resourceCaller(ctx, [32]byte(s.Peer().Key), q.Consumer) {
			return mydcp.CheckerArtifactSource{}, mydcp.ErrAdmission
		}
		source, err := r.checkerArtifactSource(ctx, q)
		if err != nil {
			return source, err
		}
		// Metadata is checked by both endpoints; wire identity is checked against
		// the original quorum permit before any bytes leave the owner.
		permit, err := r.checkerArtifactPermit(ctx, q)
		if err != nil {
			clear(source.Data)
			return mydcp.CheckerArtifactSource{}, err
		}
		digest, length := checkerArtifactBytes(q, permit)
		if wire.Digest != digest || wire.Bytes != length {
			clear(source.Data)
			return mydcp.CheckerArtifactSource{}, mydcp.ErrAdmission
		}
		return source, nil
	})
}

func (r *Runtime) checkerArtifactSource(ctx context.Context, q control.CheckerArtifactRequest) (mydcp.CheckerArtifactSource, error) {
	permit, err := r.checkerArtifactPermit(ctx, q)
	if err != nil || !r.acceptsResourceKey(ctx, permit.Provider()) {
		return mydcp.CheckerArtifactSource{}, mydcp.ErrAdmission
	}
	owner, ok := r.nativeOwner(permit.Provider())
	if !ok {
		return mydcp.CheckerArtifactSource{}, mydcp.ErrAdmission
	}
	d := permit.Source.Descriptor()
	owner.life.RLock()
	if owner.closed || owner.ctx.Err() != nil || owner.checkerSources == nil {
		owner.life.RUnlock()
		return mydcp.CheckerArtifactSource{}, mydcp.ErrAdmission
	}
	metadata := checkerArtifactMetadata{Schema: 1}
	var data []byte
	if q.Compiled != nil {
		var f checker.CompiledFact
		f, data, err = owner.checkerSources.CompiledArtifact(ctx, d.Tenant, q.Compiled.Build.Recipe.Key())
		metadata.Compiled = &f
	} else if q.Module == nil {
		var f checker.SourceFact
		f, data, err = owner.checkerSources.SourceArtifact(ctx, d)
		metadata.Source = &f
	} else {
		var f checker.ModuleFact
		f, data, err = owner.checkerSources.ModuleArtifact(ctx, d.Tenant, *q.Module)
		metadata.Module = &f
	}
	owner.life.RUnlock()
	if err != nil {
		clear(data)
		return mydcp.CheckerArtifactSource{}, err
	}
	raw, err := json.Marshal(metadata)
	if err == nil {
		err = checkerArtifactMetadataAllowed(raw, q, permit)
	}
	if err != nil {
		clear(data)
		return mydcp.CheckerArtifactSource{}, err
	}
	return mydcp.CheckerArtifactSource{Lifetime: owner.ctx, Metadata: raw, Data: data, Authorize: func(ctx context.Context) error {
		latest, err := r.checkerArtifactPermit(ctx, q)
		if err != nil || !permit.Equal(latest) {
			return mydcp.ErrAdmission
		}
		return nil
	}}, nil
}

// receiveCheckerArtifact makes one read attempt under the original use. The
// receiver's own signed cache fact is created only after exact bytes/sync; the
// shared original provider/source and accepted use are never rewritten.
func (r *Runtime) receiveCheckerArtifact(ctx context.Context, q control.CheckerArtifactRequest) error {
	if q.Lookup != nil || q.Consumer != r.Identity.Public || !r.acceptsResourceKey(ctx, q.Consumer) {
		return mydcp.ErrAdmission
	}
	permit, err := r.checkerArtifactPermit(ctx, q)
	if err != nil {
		return err
	}
	d := permit.Source.Descriptor()
	r.life.RLock()
	store := r.checkerSources
	closed := r.closed
	r.life.RUnlock()
	if closed || store == nil || r.ctx.Err() != nil {
		return mydcp.ErrAdmission
	}
	if q.Compiled != nil {
		if fact, data, err := store.CompiledArtifact(ctx, d.Tenant, q.Compiled.Build.Recipe.Key()); err == nil {
			clear(data)
			if fact.Build.Digest != q.Compiled.Build.Digest || fact.Build.Length != q.Compiled.Build.Length {
				return checker.ErrCompiledConflict
			}
			return nil
		} else if !errors.Is(err, storage.ErrMissing) || errors.Is(err, checker.ErrSourceStore) {
			return err
		}
	} else if q.Module == nil {
		if _, data, err := store.SourceArtifact(ctx, d); err == nil {
			clear(data)
			return nil
		} else if !errors.Is(err, storage.ErrMissing) || errors.Is(err, checker.ErrSourceStore) {
			return err
		}
	} else {
		if _, data, err := store.ModuleArtifact(ctx, d.Tenant, *q.Module); err == nil {
			clear(data)
			return nil
		} else if !errors.Is(err, storage.ErrMissing) || errors.Is(err, checker.ErrSourceStore) {
			return err
		}
	}
	storeArtifact := func(ctx context.Context, data []byte) error {
		current, err := r.checkerArtifactPermit(ctx, q)
		if err != nil || !current.Equal(permit) {
			return mydcp.ErrAdmission
		}
		if q.Compiled != nil {
			_, err = store.StageCompiled(ctx, d, current.Policy, q.Compiled.Build, data)
		} else if q.Module == nil {
			_, err = store.Stage(ctx, d, data, current.Policy)
		} else {
			_, err = store.StageModule(ctx, d, checker.ModuleArchive{Pin: *q.Module, ZIP: data}, current.Policy)
		}
		return err
	}
	if r.acceptsResourceKey(ctx, permit.Provider()) {
		source, err := r.checkerArtifactSource(ctx, q)
		if err != nil {
			return err
		}
		defer clear(source.Data)
		if err = checkerArtifactMetadataAllowed(source.Metadata, q, permit); err != nil {
			return err
		}
		if err = source.Authorize(ctx); err != nil {
			return err
		}
		return storeArtifact(ctx, source.Data)
	}
	peer, ok := r.resourcePeerForKey(ctx, permit.Provider())
	if !ok || !peer.Member {
		return mydcp.ErrAdmission
	}
	session, err := r.Mesh.Dial(ctx, peer)
	if err != nil {
		return err
	}
	metadata, _ := json.Marshal(q)
	digest, length := checkerArtifactBytes(q, permit)
	expires := time.Now().Add(5 * time.Minute)
	if end, ok := ctx.Deadline(); ok && end.Before(expires) {
		expires = end
	}
	wire := mydcp.CheckerArtifactRequest{Schema: 1, Metadata: metadata, Digest: digest, Bytes: length, ExpiresAt: expires.Unix()}
	return session.PullCheckerArtifact(ctx, wire, mydcp.CheckerArtifactSink{Metadata: func(raw []byte) error {
		return checkerArtifactMetadataAllowed(raw, q, permit)
	}, Store: storeArtifact,
	})
}

func (r *Runtime) prepareCheckerInputs(ctx context.Context, b deployment.Binding, index uint64) error {
	u, has := control.CheckerBindingUse(b)
	if !has {
		return nil
	}
	if u.Owner != r.Identity.Public {
		return mydcp.ErrAdmission
	}
	view, err := r.Engine().Read(ctx, false)
	if err != nil || view.State.Index() < index {
		return mydcp.ErrAdmission
	}
	book, err := r.controlPolicy.Lifecycles(view.State)
	if err != nil {
		return err
	}
	facts := append([]checker.SourceFact(nil), u.Sources...)
	for _, ref := range u.Scripts {
		record, ok := book.Script(u.Tenant, ref.Name)
		if !ok {
			return mydcp.ErrAdmission
		}
		found := false
		for _, v := range record.Versions {
			if v.Revision == ref.Revision {
				facts = append(facts, v.Source)
				found = true
				break
			}
		}
		if !found {
			return mydcp.ErrAdmission
		}
	}
	seen := map[[32]byte]bool{}
	for _, fact := range facts {
		content := fact.ContentDigest()
		if seen[content] {
			continue
		}
		seen[content] = true
		if err := r.receiveCheckerSource(ctx, u, fact, index); err != nil {
			return err
		}
	}
	return nil
}

// App preparation and a reserved compiler job consume the same current use,
// root/module transport and real receiver cache; no second staging path.
func (r *Runtime) receiveCheckerSource(ctx context.Context, u checker.Use, fact checker.SourceFact, index uint64) error {
	q := control.CheckerArtifactRequest{Schema: 1, Tenant: u.Tenant, UseID: u.ID, Use: u.Digest(), Content: fact.ContentDigest(), Consumer: u.Owner, MinimumIndex: index}
	for _, pin := range fact.Modules {
		copy := pin
		q.Module = &copy
		if err := r.receiveCheckerArtifact(ctx, q); err != nil {
			return err
		}
	}
	q.Module = nil
	return r.receiveCheckerArtifact(ctx, q)
}
