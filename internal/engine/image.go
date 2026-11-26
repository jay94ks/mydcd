// SPDX-License-Identifier: Apache-2.0

package engine

import (
	"context"
	"strings"

	cerrdefs "github.com/containerd/errdefs"
	"github.com/distribution/reference"
	"github.com/moby/moby/client"
)

// Image uses content-addressed references only. Registry access is explicit;
// image IDs are local-only. Shutdown never removes shared cached images.
func (c *Client) Image(ctx context.Context, ref string, pull bool) (client.ImageInspectResult, error) {
	return c.ImageWithAuth(ctx, ref, pull, RegistryAuth{})
}

func (c *Client) ImageWithAuth(ctx context.Context, ref string, pull bool, auth RegistryAuth) (client.ImageInspectResult, error) {
	if auth.external != nil {
		defer auth.external.Close()
	}
	r, err := reference.ParseAnyReference(ref)
	if err != nil {
		return client.ImageInspectResult{}, err
	}
	if _, ok := r.(reference.Digested); !ok {
		return client.ImageInspectResult{}, ErrOwnership
	}
	if auth.authority != "" {
		n, ok := r.(reference.Named)
		if !ok || reference.Domain(n) != auth.authority {
			return client.ImageInspectResult{}, ErrOwnership
		}
	}
	got, err := c.API.ImageInspect(ctx, ref)
	if cerrdefs.IsNotFound(err) && auth.external != nil {
		return c.externalImage(ctx, ref, pull, auth.external, auth.observePull)
	}
	if cerrdefs.IsNotFound(err) && pull {
		if _, named := r.(reference.Named); !named {
			return got, err
		}
		if pullErr := c.pullImage(ctx, ref, auth); pullErr != nil {
			return got, pullErr
		}
		got, err = c.API.ImageInspect(ctx, ref)
	}
	if err != nil {
		return got, err
	}
	if strings.HasPrefix(ref, "sha256:") && got.ID != ref {
		return got, ErrOwnership
	}
	return got, nil
}
