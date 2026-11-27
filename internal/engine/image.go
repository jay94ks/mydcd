// SPDX-License-Identifier: Apache-2.0

package engine

import (
	"context"
	"strings"

	cerrdefs "github.com/containerd/errdefs"
	"github.com/distribution/reference"
	"github.com/moby/moby/client"

	"github.com/jay94ks/seafield/internal/engineimage"
	"github.com/jay94ks/seafield/internal/registryclient"
)

// Image uses content-addressed references only. Registry access is explicit;
// image IDs are local-only. Shutdown never removes shared cached images.
func (c *Client) Image(ctx context.Context, ref string, pull bool) (client.ImageInspectResult, error) {
	return c.ImageWithAuth(ctx, ref, pull, RegistryAuth{})
}

// ImageWithAuth inspects ref and, when it is missing and pull is set, has the
// engine pull its pinned root. sfcd reads that root from auth's source under a
// pull ticket the engine's purpose 37 requests are answered from; the engine
// itself never reaches a registry.
func (c *Client) ImageWithAuth(ctx context.Context, ref string, pull bool, auth RegistryAuth) (client.ImageInspectResult, error) {
	if auth.source != nil {
		defer auth.source.Close()
	}
	r, err := reference.ParseAnyReference(ref)
	if err != nil {
		return client.ImageInspectResult{}, err
	}
	digested, ok := r.(reference.Digested)
	if !ok {
		return client.ImageInspectResult{}, ErrOwnership
	}
	named, isNamed := r.(reference.Named)
	if auth.authority != "" && (!isNamed || reference.Domain(named) != auth.authority) {
		return client.ImageInspectResult{}, ErrOwnership
	}
	got, err := c.API.ImageInspect(ctx, ref)
	if cerrdefs.IsNotFound(err) && pull && isNamed {
		root := named.Name() + "@" + digested.Digest().String()
		if err = c.pullTicketed(ctx, root, auth); err != nil {
			return got, err
		}
		got, err = c.API.ImageInspect(ctx, root)
	}
	if err != nil {
		return got, err
	}
	if strings.HasPrefix(ref, "sha256:") && got.ID != ref {
		return got, ErrOwnership
	}
	return got, nil
}

// pullTicketed walks root through its source ("resolve"), then lets the
// engine pull exactly that graph ("load") and closes the ticket.
func (c *Client) pullTicketed(ctx context.Context, root string, auth RegistryAuth) (failure error) {
	stage := "resolve"
	defer func() {
		if auth.observePull != nil {
			auth.observePull(registryclient.PullOutcome{Stage: stage, Code: registryclient.ResultCode(failure)})
		}
	}()
	if c.Images == nil {
		return ErrOwnership
	}
	var open engineimage.Opener
	if auth.source != nil {
		open = auth.source.OpenGraphContentAt
	} else {
		_, authority, _, err := registryclient.Normalize(root)
		if err != nil {
			return err
		}
		if c.Anonymous != nil {
			open, err = c.Anonymous(authority)
		} else {
			var source *registryclient.Access
			if source, err = registryclient.New(authority, nil, nil, nil); err == nil {
				defer source.Close()
				open = source.OpenGraphContentAt
			}
		}
		if err != nil {
			return err
		}
	}
	release, err := c.Images.Issue(ctx, root, open)
	if err != nil {
		return registryclient.Sanitize(err)
	}
	defer release()
	stage = "load"
	return c.pullImage(ctx, root)
}

// PullClusterApp has the engine pull a cluster app image, ref
// (sfc-cluster-app/<app>@sha256:...), from sfcd's verified bundle. Unlike
// ImageWithAuth it reads no registry: the ticket is IssueClusterApp over
// open, held only while the engine pulls. A ref already present is only
// inspected.
func (c *Client) PullClusterApp(ctx context.Context, ref string, open engineimage.Opener) (client.ImageInspectResult, error) {
	if c.Images == nil || open == nil {
		return client.ImageInspectResult{}, ErrOwnership
	}
	got, err := c.API.ImageInspect(ctx, ref)
	if !cerrdefs.IsNotFound(err) {
		return got, err
	}
	release, err := c.Images.IssueClusterApp(ctx, ref, open)
	if err != nil {
		return got, err
	}
	defer release()
	if err = c.pullImage(ctx, ref); err != nil {
		return got, err
	}
	return c.API.ImageInspect(ctx, ref)
}
