// SPDX-License-Identifier: Apache-2.0

package engine

import (
	"context"

	cerrdefs "github.com/containerd/errdefs"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/moby/moby/client"

	"github.com/jay94ks/mydcd/internal/registryclient"
)

// LoadImage makes a verified local image (a node app image read from its
// bundle) present in the Engine: it inspects the exact config or manifest
// ID and loads the original graph only when neither is there. The caller
// has already checked the image digest against its pin.
func (c *Client) LoadImage(ctx context.Context, image v1.Image) (client.ImageInspectResult, error) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	archive, err := prepareExternalArchive(image)
	if err != nil {
		return client.ImageInspectResult{}, registryclient.Sanitize(err)
	}
	got, err := c.inspectExternalImage(ctx, archive)
	if err == nil || !cerrdefs.IsNotFound(err) {
		return got, err
	}
	if err = c.loadExternalImage(ctx, cancel, archive); err != nil {
		return got, err
	}
	return c.inspectExternalImage(ctx, archive)
}
