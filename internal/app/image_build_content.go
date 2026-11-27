// SPDX-License-Identifier: Apache-2.0

package app

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/jay94ks/seafield/internal/cluster"
	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/imagebuild"
	"github.com/jay94ks/seafield/internal/schema"
	"github.com/jay94ks/seafield/internal/sfcp"
)

// One bounded immutable tree, guarded by imageBuildMu together with native
// upload/GC. No credential, mutable draft or full ZIP is cached here.
type imageBuildContentCache struct {
	scope   [32]byte
	version [32]byte
	content *imagebuild.Content
	file    *imagebuild.FileReader
	path    string
}

func (c *imageBuildContentCache) Close() error {
	if c == nil {
		return nil
	}
	err := c.file.Close()
	c.file = nil
	return err
}

func (r *Runtime) imageBuildContent(ctx context.Context, read control.ImageBuildContentRead) (control.ImageBuildContentPage, error) {
	view, err := r.currentView(ctx)
	if err != nil || view.Local {
		return control.ImageBuildContentPage{}, sfcp.ErrAdmission
	}
	current, err := r.controlPolicy.CurrentImageBuildContentRead(view.State, read, time.Now().Unix())
	if err != nil {
		return control.ImageBuildContentPage{}, err
	}
	if current.Scope.Root.Key == r.Identity.Public {
		return r.imageBuildContentOwner(ctx, current)
	}
	peer, ok := r.Mesh.Peer(sfcp.Identity(current.Scope.Root.Key))
	if !ok || !peer.Member || peer.ID != current.Scope.Root.Node {
		return control.ImageBuildContentPage{}, sfcp.ErrAdmission
	}
	raw, _ := json.Marshal(current)
	reply, err := cluster.CallManagement(ctx, r.Mesh, r.Identity, r.controlPolicy.Cluster, peer, cluster.ManagementRequest{Method: "image-build-content-owner", Input: raw})
	if err != nil || reply.Code != "ok" {
		return control.ImageBuildContentPage{}, sfcp.ErrAdmission
	}
	if current.Query.Part == "file" {
		return decodeImageBuildFileContent(reply.Data, current)
	}

	out, err := schema.Decode[control.ImageBuildContentPage](reply.Data)
	if err != nil || !out.Valid(current) {
		return control.ImageBuildContentPage{}, sfcp.ErrAdmission
	}
	return out, nil
}
func (r *Runtime) imageBuildContentOwner(ctx context.Context, read control.ImageBuildContentRead) (control.ImageBuildContentPage, error) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	stop := context.AfterFunc(r.ctx, cancel)
	defer stop()
	current := func() error {
		view, err := r.currentView(ctx)
		if err != nil || view.Local {
			return sfcp.ErrAdmission
		}
		now, err := r.controlPolicy.CurrentImageBuildContentRead(view.State, read, time.Now().Unix())
		if err != nil {
			return err
		}
		if now.Scope.Root.Key != r.Identity.Public {
			return sfcp.ErrAdmission
		}
		return nil
	}
	if err := current(); err != nil {
		return control.ImageBuildContentPage{}, err
	}
	r.life.RLock()
	defer r.life.RUnlock()
	if r.closed || r.ctx.Err() != nil || r.nodeRoots == nil || r.reports == nil {
		return control.ImageBuildContentPage{}, sfcp.ErrAdmission
	}
	r.imageBuildMu.Lock()
	defer r.imageBuildMu.Unlock()
	completed := false
	defer func() {
		if !completed && r.imageBuildTree != nil {
			_ = r.imageBuildTree.Close()
		}
	}()
	if err := current(); err != nil {
		return control.ImageBuildContentPage{}, err
	}
	// Existing bytes may be read during drain. Never create or borrow a new
	// root dependency in order to make an absent original look available.
	pin, err := r.nodeRoots.OpenRecordedPin(read.Scope.Root, buildArtifactConsumer(read.Scope))
	if err != nil || pin.Directory == nil {
		return control.ImageBuildContentPage{}, errors.Join(imagebuild.ErrStorage, err)
	}
	defer func() {
		if pin.Directory != nil {
			_ = pin.Directory.Close()
		}
	}()
	spool, err := imagebuild.OpenExistingSpool(pin.Directory.FD(), read.Scope.Root, r.reports)
	if err != nil {
		return control.ImageBuildContentPage{}, err
	}
	defer spool.Close()
	if err := spool.CheckSeal(read.Scope, read.Seal); err != nil {
		return control.ImageBuildContentPage{}, err
	}
	cache := r.imageBuildTree
	if cache == nil || cache.scope != read.Scope.Hash() || cache.version != read.Query.Version {
		if err := cache.Close(); err != nil {
			return control.ImageBuildContentPage{}, err
		}
		r.imageBuildTree = nil
		tree, err := spool.Inspect(ctx, read.Scope, read.Seal)
		if err != nil {
			return control.ImageBuildContentPage{}, err
		}
		content, err := imagebuild.NewContent(tree, read.Scope, read.Seal)
		if err != nil {
			return control.ImageBuildContentPage{}, err
		}
		cache = &imageBuildContentCache{scope: read.Scope.Hash(), version: read.Query.Version, content: content}
		r.imageBuildTree = cache
	}
	offset, err := read.Offset()
	if err != nil {
		return control.ImageBuildContentPage{}, err
	}
	var page imagebuild.ContentPage
	if read.Query.Part == "file" {
		entry, cause := cache.content.FileEntry(read.Query)
		if cause != nil {
			return control.ImageBuildContentPage{}, cause
		}
		if cache.file == nil || cache.path != read.Query.Path {
			if err := cache.file.Close(); err != nil {
				return control.ImageBuildContentPage{}, err
			}
			cache.file, cache.path = nil, ""
			cache.file, err = spool.OpenFile(read.Scope, read.Seal, entry)
			if err != nil {
				return control.ImageBuildContentPage{}, err
			}
			cache.path = read.Query.Path
		}
		file, cause := cache.file.Read(ctx, offset)
		if cause != nil {
			_ = cache.Close()
			return control.ImageBuildContentPage{}, cause
		}
		page = imagebuild.ContentPage{Schema: 1, Version: read.Query.Version, Tree: read.Seal.Tree, Part: "file", File: &file}
	} else {
		page, err = cache.content.Read(read.Query, uint32(offset))
	}
	if err != nil {
		return control.ImageBuildContentPage{}, err
	}
	if err := spool.Close(); err != nil {
		return control.ImageBuildContentPage{}, err
	}
	if err := pin.Directory.Close(); err != nil {
		return control.ImageBuildContentPage{}, err
	}
	pin.Directory = nil
	if err := current(); err != nil {
		return control.ImageBuildContentPage{}, err
	}
	out, err := read.Page(page)
	completed = err == nil
	return out, err
}
