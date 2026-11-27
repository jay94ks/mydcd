// SPDX-License-Identifier: Apache-2.0

package imagebuild

import (
	"context"
	"errors"
	"time"

	"github.com/jay94ks/seafield/internal/reconcile"
	"github.com/jay94ks/seafield/internal/registryclient"
)

func (n *NativeJobs) publicationAuthority(ctx context.Context, r *NativeRecord, write bool) error {
	g, err := n.current(ctx, r, true)
	if err != nil {
		return err
	}
	if write && (!g.Allowed || g.Run.Cancel || g.Run.Terminal() || g.Run.Phase != "running" && g.Run.Phase != "unknown" || r.Cancel) {
		return &registryclient.Error{Code: "DENIED"}
	}
	return nil
}

func (n *NativeJobs) beforePublication(ctx context.Context, spec JobSpec, ordinal int, root bool) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	r, err := n.load(spec)
	if err != nil {
		return err
	}
	if !n.publishing[spec.Digest()] || r.Publication == nil || ordinal < 0 || ordinal >= len(r.Publication.Tags) {
		return ErrStorage
	}
	if err := n.publicationAuthority(ctx, &r, true); err != nil {
		return err
	}
	tag := &r.Publication.Tags[ordinal]
	if tag.Code != "" || tag.Sent {
		return reconcile.ErrPending
	}
	changed := !tag.Started || root
	tag.Started = true
	if root {
		tag.Sent = true
	}
	if changed {
		return n.save(r)
	}
	return nil
}

func (n *NativeJobs) endPublication(spec JobSpec) {
	n.mu.Lock()
	delete(n.publishing, spec.Digest())
	n.mu.Unlock()
}

// PublishOutput consumes the original held lazy OCI object. Only an untouched
// tag can enter the SDK. Started/Sent attempts require read-only recovery, not
// another upload; an unknown root also prevents the next tag being attempted.
func (n *NativeJobs) PublishOutput(ctx context.Context, spec JobSpec, built *BuiltImage, client *registryclient.Access) (JobResult, error) {
	if ctx == nil || built == nil || client == nil || built.output == nil || built.output.owner != n || built.output.job != spec.Digest() {
		return JobResult{}, ErrInvalid
	}
	// Close joins this real lazy-I/O consumer before releasing its layout FD.
	built.mu.Lock()
	defer built.mu.Unlock()
	if built.closed {
		return JobResult{}, ErrStorage
	}
	if err := func() error {
		n.mu.Lock()
		defer n.mu.Unlock()
		if n.publishing[spec.Digest()] {
			return ErrUsed
		}
		r, err := n.load(spec)
		if err != nil {
			return err
		}
		if r.Workspace == nil || r.Workspace.Removing || !r.Removed {
			return ErrConflict
		}
		if r.Publication != nil && r.Publication.Output != built.Metadata {
			return ErrConflict
		}
		if err := n.publicationAuthority(ctx, &r, true); err != nil {
			return err
		}
		if r.Publication == nil {
			p, err := newPublication(spec, built.Metadata)
			if err != nil {
				return err
			}
			r.Publication = &p
			if err := n.save(r); err != nil {
				return err
			}
		}
		n.publishing[spec.Digest()] = true
		return nil
	}(); err != nil {
		return JobResult{}, err
	}
	defer n.endPublication(spec)
	for ordinal := 0; ; ordinal++ {
		n.mu.Lock()
		r, err := n.load(spec)
		if err != nil {
			n.mu.Unlock()
			return JobResult{}, err
		}
		if result, closed := r.Publication.result(spec); closed {
			n.mu.Unlock()
			return result, nil
		}
		if ordinal >= len(r.Publication.Tags) {
			n.mu.Unlock()
			return JobResult{}, ErrStorage
		}
		tag := r.Publication.Tags[ordinal]
		n.mu.Unlock()
		if tag.Code == "OK" {
			continue
		}
		if tag.Started || tag.Sent {
			return JobResult{}, reconcile.ErrPending
		}
		if err := ctx.Err(); err != nil {
			return JobResult{}, err
		}
		out := client.PublishImage(ctx, tag.Target, built.Image, built.Index, func(ctx context.Context, root bool) error { return n.beforePublication(ctx, spec, ordinal, root) })
		n.mu.Lock()
		r, err = n.load(spec)
		if err != nil {
			n.mu.Unlock()
			return JobResult{}, err
		}
		original := &r.Publication.Tags[ordinal]
		if !out.Valid() || out.Digest != "" && out.Digest != r.Publication.Output.Digest || out.Started && !original.Started || out.Attempted && !original.Sent {
			n.mu.Unlock()
			return JobResult{}, ErrStorage
		}
		original.Code, original.At = out.Code, out.At
		// An intent commit may have succeeded even though the DB returned an
		// error to before(). Keep that recorded Sent conservative, never clear
		// it using the SDK's lack of a locally acknowledged dispatch.
		if original.Sent && !out.Attempted {
			original.Code = "UNKNOWN"
		}
		err = n.save(r)
		n.mu.Unlock()
		if err != nil {
			return JobResult{}, err
		}
		if original.Code == "UNKNOWN" {
			return JobResult{}, reconcile.ErrPending
		}
	}
}

// RecoverPublication never writes to a registry. Its observer must use the
// current authenticated original registry/read boundary. Matching immutable
// content at the original tag can finish a lost PUT; absence/another digest
// cannot prove non-execution and never permits a replacement upload.
func (n *NativeJobs) RecoverPublication(ctx context.Context, spec JobSpec, observe func(context.Context, string) (registryclient.Resolution, error)) (JobResult, error) {
	if ctx == nil || observe == nil {
		return JobResult{}, ErrInvalid
	}
	if err := func() error {
		n.mu.Lock()
		defer n.mu.Unlock()
		if n.publishing[spec.Digest()] {
			return ErrUsed
		}
		r, err := n.load(spec)
		if err != nil {
			return err
		}
		if r.Publication == nil {
			return reconcile.ErrPending
		}
		if err := n.publicationAuthority(ctx, &r, false); err != nil {
			return err
		}
		n.publishing[spec.Digest()] = true
		return nil
	}(); err != nil {
		return JobResult{}, err
	}
	defer n.endPublication(spec)
	for ordinal := 0; ; ordinal++ {
		n.mu.Lock()
		r, err := n.load(spec)
		if err != nil {
			n.mu.Unlock()
			return JobResult{}, err
		}
		if result, closed := r.Publication.result(spec); closed {
			n.mu.Unlock()
			return result, nil
		}
		if ordinal >= len(r.Publication.Tags) {
			n.mu.Unlock()
			return JobResult{}, ErrStorage
		}
		tag := r.Publication.Tags[ordinal]
		if tag.Code == "OK" {
			n.mu.Unlock()
			continue
		}
		if !tag.Started {
			n.mu.Unlock()
			return JobResult{}, reconcile.ErrPending
		}
		if !tag.Sent {
			// No live SDK call exists and durable Sent precedes every root PUT.
			// Dependency blobs may remain, but no root publication was issued.
			r.Publication.Tags[ordinal].Code = "UNAVAILABLE"
			r.Publication.Tags[ordinal].At = uint64(time.Now().UnixMilli())
			err = n.save(r)
			n.mu.Unlock()
			if err != nil {
				return JobResult{}, err
			}
			continue
		}
		want := r.Publication.Output
		n.mu.Unlock()
		observed, err := observe(ctx, tag.Target)
		if err != nil {
			return JobResult{}, errors.Join(reconcile.ErrPending, registryclient.Sanitize(err))
		}
		if !observed.Valid(tag.Target) || observed.Normalized != tag.Target || observed.Digest != want.Digest || observed.ManifestBytes != want.ManifestBytes || observed.MediaType != want.MediaType {
			return JobResult{}, reconcile.ErrPending
		}
		n.mu.Lock()
		r, err = n.load(spec)
		if err == nil {
			r.Publication.Tags[ordinal].Code = "OK"
			r.Publication.Tags[ordinal].At = uint64(time.Now().UnixMilli())
			err = n.save(r)
		}
		n.mu.Unlock()
		if err != nil {
			return JobResult{}, err
		}
	}
}

// CloseUnsentPublication records a joined failure/cancellation without
// erasing a sent unknown root. It never rolls back an acknowledged tag prefix.
func (n *NativeJobs) CloseUnsentPublication(spec JobSpec, code string) (JobResult, error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	if !registryclient.ValidResultCode(code) || code == "OK" {
		return JobResult{}, ErrInvalid
	}
	if n.publishing[spec.Digest()] {
		return JobResult{}, ErrUsed
	}
	r, err := n.load(spec)
	if err != nil {
		return JobResult{}, err
	}
	if r.Publication == nil {
		return JobResult{}, reconcile.ErrPending
	}
	if result, closed := r.Publication.result(spec); closed {
		return result, nil
	}
	for i, tag := range r.Publication.Tags {
		if tag.Code == "OK" {
			continue
		}
		if tag.Sent {
			return JobResult{}, reconcile.ErrPending
		}
		r.Publication.Tags[i].Code = code
		r.Publication.Tags[i].At = uint64(time.Now().UnixMilli())
		if err := n.save(r); err != nil {
			return JobResult{}, err
		}
		result, closed := r.Publication.result(spec)
		if !closed {
			return JobResult{}, ErrStorage
		}
		return result, nil
	}
	return JobResult{}, ErrStorage
}

func (n *NativeJobs) PublicationResult(spec JobSpec) (JobResult, error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	r, err := n.load(spec)
	if err != nil {
		return JobResult{}, err
	}
	if r.Publication == nil {
		return JobResult{}, reconcile.ErrPending
	}
	if result, closed := r.Publication.result(spec); closed {
		return result, nil
	}
	return JobResult{}, reconcile.ErrPending
}
