// SPDX-License-Identifier: Apache-2.0

package engine

import (
	"context"
	"github.com/moby/moby/client"
)

// Gone checks every generation for this owner/key. An uncertain dispatched
// journal must be settled before this observation can support retirement.
func (c *Client) Gone(ctx context.Context, kind, key string) (bool, error) {
	f := client.Filters{}.Add("label", "org.mydc.owner="+c.Owner, "org.mydc.key="+key, "org.mydc.kind="+kind)
	if kind == "container" {
		v, err := c.API.ContainerList(ctx, client.ContainerListOptions{All: true, Filters: f})
		return len(v.Items) == 0, err
	}
	if kind == "bridge" {
		v, err := c.API.NetworkList(ctx, client.NetworkListOptions{Filters: f})
		return len(v.Items) == 0, err
	}
	if kind == "volume" {
		v, err := c.API.VolumeList(ctx, client.VolumeListOptions{Filters: f})
		return len(v.Items) == 0, err
	}
	return false, ErrOwnership
}
