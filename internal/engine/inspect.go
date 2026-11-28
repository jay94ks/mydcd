// SPDX-License-Identifier: Apache-2.0

package engine

import (
	"context"
	"github.com/moby/moby/client"
	"strconv"
)

// Gone checks every generation for this owner/key. An uncertain dispatched
// journal must be settled before this observation can support retirement.
// GoneGeneration is Gone for one generation of key: another generation of
// the same key (a surge successor) may exist.
func (c *Client) GoneGeneration(ctx context.Context, kind, key string, generation uint64) (bool, error) {
	if kind != "container" || generation == 0 {
		return false, ErrOwnership
	}
	f := client.Filters{}.Add("label", "org.sfc.owner="+c.Owner, "org.sfc.key="+key, "org.sfc.kind="+kind, "org.sfc.generation="+strconv.FormatUint(generation, 10))
	v, err := c.API.ContainerList(ctx, client.ContainerListOptions{All: true, Filters: f})
	return len(v.Items) == 0, err
}

func (c *Client) Gone(ctx context.Context, kind, key string) (bool, error) {
	f := client.Filters{}.Add("label", "org.sfc.owner="+c.Owner, "org.sfc.key="+key, "org.sfc.kind="+kind)
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
