// SPDX-License-Identifier: Apache-2.0

package app

import (
	"context"
	"io"
	"sync"
	"time"

	"github.com/jay94ks/mydcd/internal/cluster/control"
	"github.com/jay94ks/mydcd/internal/mydcp"
	"github.com/jay94ks/mydcd/internal/registryclient"
	"github.com/jay94ks/mydcd/internal/userauth"
)

type imageContentBody struct {
	io.ReadCloser
	release func()
	once    sync.Once
	err     error
}

func (r *imageContentBody) Close() error {
	r.once.Do(func() { r.err = r.ReadCloser.Close(); r.release() })
	return r.err
}

func (r *Runtime) currentImageContent(ctx context.Context, read control.ImageContentRead) error {
	view, err := r.currentView(ctx)
	if err != nil {
		return mydcp.ErrAdmission
	}
	current, err := r.controlPolicy.CurrentImageContent(view.State, read, time.Now().Unix())
	if err != nil || current.Resolve.Target.Code != "" || current.Resolve.Target.Owner != r.Identity.Public {
		return mydcp.ErrAdmission
	}
	if run := current.Resolve.Target.Managed; run != nil {
		_, _, err = r.registryCurrent(ctx, *run)
		return err
	}
	if source := current.Resolve.Target.External; source != nil {
		work, err := r.externalRegistryWork(ctx, *source)
		if err != nil || work.Inputs.ReadSet != current.Resolve.Target.ExternalReadSet {
			return mydcp.ErrAdmission
		}
	}
	return nil
}
func (r *Runtime) openImageContent(ctx context.Context, read control.ImageContentRead) (userauth.ImageContentSource, error) {
	if err := r.currentImageContent(ctx, read); err != nil {
		return userauth.ImageContentSource{}, err
	}
	q := registryclient.GraphContentQuery{Root: read.Query.Ref, Kind: read.Query.Kind, Digest: read.Query.Digest}
	return r.openImageContentTarget(ctx, read.Resolve.Target, q, func(call context.Context) error { return r.currentImageContent(call, read) })
}

// Both fresh user reads and accepted build reads keep the same original
// source I/O hold and native Store gate. Only their authorization differs.
func (r *Runtime) openImageContentTarget(ctx context.Context, target control.ImageResolveTarget, q registryclient.GraphContentQuery, current func(context.Context) error) (userauth.ImageContentSource, error) {
	ctx, cancel := context.WithCancel(ctx)
	stop := context.AfterFunc(r.ctx, cancel)
	cleanup := func() { stop(); cancel() }
	var info registryclient.ContentInfo
	var body io.ReadCloser
	var err error
	if run := target.Managed; run != nil {
		store, cause := r.maintenanceStore(*run)
		if cause != nil {
			cleanup()
			return userauth.ImageContentSource{}, cause
		}
		info, body, err = store.OpenGraphContent(ctx, q)
	} else {
		var client *registryclient.Access
		var release func()
		if source := target.External; source != nil {
			work, cause := r.externalRegistryWork(ctx, *source)
			if cause != nil || work.Inputs.ReadSet != target.ExternalReadSet {
				cleanup()
				return userauth.ImageContentSource{}, mydcp.ErrAdmission
			}
			release, err = r.acquireExternalReader(work)
			if err == nil {
				client, err = r.sourceRegistryClient(ctx, work)
			}
		} else {
			_, authority, _, cause := registryclient.Normalize(q.Root)
			if cause != nil {
				cleanup()
				return userauth.ImageContentSource{}, cause
			}
			client, err = registryclient.New(authority, nil, nil, nil)
		}
		old := cleanup
		cleanup = func() {
			old()
			if client != nil {
				client.Close()
			}
			if release != nil {
				release()
			}
		}
		if err == nil {
			info, body, err = client.OpenGraphContent(ctx, q)
		}
	}
	if err != nil || body == nil {
		if body != nil {
			_ = body.Close()
		}
		cleanup()
		if err == nil {
			err = mydcp.ErrAdmission
		}
		return userauth.ImageContentSource{}, err
	}
	owned := &imageContentBody{ReadCloser: body, release: cleanup}
	if err = current(ctx); err != nil {
		_ = owned.Close()
		return userauth.ImageContentSource{}, err
	}
	return userauth.ImageContentSource{Lifetime: r.ctx, Info: info, Body: owned, Authorize: current}, nil
}
