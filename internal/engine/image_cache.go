// SPDX-License-Identifier: Apache-2.0

package engine

import (
	"context"
	"errors"
	"slices"
	"strings"
	"time"
	"unicode/utf8"

	cerrdefs "github.com/containerd/errdefs"
	"github.com/jay94ks/seafield/internal/imagecache"
	"github.com/moby/moby/client"
)

// CacheCandidates uses all native containers, including stopped/foreign ones.
// It does not use the image summary's optional Containers=-1 as a zero count.
// The caller adds current shared references before signing a deletion plan.
func (c *Client) CacheCandidates(ctx context.Context, ids []string, after string) ([]imagecache.Image, string, error) {
	if c == nil || c.API == nil || !imagecache.ValidSelection(ids, false) || after != "" && (len(ids) > 0 || !imagecache.ValidID(after)) {
		return nil, "", imagecache.ErrPlan
	}
	listed, err := c.API.ImageList(ctx, client.ImageListOptions{All: true})
	if err != nil {
		return nil, "", err
	}
	containers, err := c.API.ContainerList(ctx, client.ContainerListOptions{All: true})
	if err != nil {
		return nil, "", err
	}
	uses := map[string]uint64{}
	for _, container := range containers.Items {
		if !imagecache.ValidID(container.ImageID) {
			return nil, "", imagecache.ErrPlan
		}
		uses[container.ImageID]++
	}
	selected := map[string]bool{}
	for _, id := range ids {
		selected[id] = true
	}
	var rows []imagecache.Image
	seen := map[string]bool{}
	for _, image := range listed.Items {
		if !imagecache.ValidID(image.ID) || seen[image.ID] {
			return nil, "", imagecache.ErrPlan
		}
		seen[image.ID] = true
		if image.ID <= after || len(ids) > 0 && !selected[image.ID] {
			continue
		}
		row := imagecache.Image{ID: image.ID, Bytes: image.Size, Containers: uses[image.ID]}
		aliases := map[string]bool{}
		for _, raw := range append(slices.Clone(image.RepoTags), image.RepoDigests...) {
			if raw == "<none>:<none>" || raw == "<none>@<none>" {
				continue
			}
			alias, e := imagecache.CanonicalReference(raw)
			if e != nil {
				return nil, "", e
			}
			if alias != row.ID {
				aliases[alias] = true
			}
		}
		for alias := range aliases {
			row.Aliases = append(row.Aliases, alias)
		}
		slices.Sort(row.Aliases)
		if !row.Valid() {
			return nil, "", imagecache.ErrPlan
		}
		rows = append(rows, row)
	}
	slices.SortFunc(rows, func(a, b imagecache.Image) int { return strings.Compare(a.ID, b.ID) })
	if len(ids) > 0 && len(rows) != len(ids) {
		return nil, "", imagecache.ErrPlan
	}
	next := ""
	if len(rows) > imagecache.MaxImages {
		rows = rows[:imagecache.MaxImages]
		next = rows[len(rows)-1].ID
	}
	return rows, next, nil
}

func cachePart(id, state, code string, err error) imagecache.Part {
	p := imagecache.Part{ID: id, State: state, Code: code, At: uint64(time.Now().UnixMilli())}
	if err != nil {
		p.Error = strings.ToValidUTF8(err.Error(), "?")
		if len(p.Error) > 512 {
			p.Error = p.Error[:512]
			for !utf8.ValidString(p.Error) {
				p.Error = p.Error[:len(p.Error)-1]
			}
		}
	}
	return p
}

// RemoveCachedImage rechecks actual aliases/native use and the supplied fresh
// quorum reference guard, then syncs the original dispatch before the SDK call.
// known=false retains the sent original: transport failure is not non-execution.
func (c *Client) RemoveCachedImage(ctx context.Context, original imagecache.Image, guard func(context.Context, imagecache.Image) (uint64, error), sent func() error) (part imagecache.Part, known bool, err error) {
	if !original.Unused() || guard == nil || sent == nil {
		return part, false, imagecache.ErrPlan
	}
	_, inspectErr := c.API.ImageInspect(ctx, original.ID)
	if cerrdefs.IsNotFound(inspectErr) {
		return cachePart(original.ID, "already-absent", "", nil), true, nil
	}
	if inspectErr != nil {
		return part, false, inspectErr
	}
	rows, _, err := c.CacheCandidates(ctx, []string{original.ID}, "")
	if err != nil {
		return part, false, err
	}
	current := rows[0]
	if !original.SameContent(current) {
		return cachePart(original.ID, "skipped", "image-changed", nil), true, nil
	}
	if current.Containers > 0 {
		return cachePart(original.ID, "skipped", "container-reference", nil), true, nil
	}
	references, err := guard(ctx, current)
	if err != nil {
		return part, false, err
	}
	if references > 0 {
		return cachePart(original.ID, "skipped", "desired-reference", nil), true, nil
	}
	if err = ctx.Err(); err != nil {
		return part, false, err
	}
	if err = sent(); err != nil {
		return part, false, err
	}
	_, callErr := c.API.ImageRemove(ctx, original.ID, client.ImageRemoveOptions{Force: false, PruneChildren: false})
	_, observeErr := c.API.ImageInspect(ctx, original.ID)
	if cerrdefs.IsNotFound(observeErr) {
		state := "removed"
		if callErr != nil {
			state = "already-absent"
		}
		return cachePart(original.ID, state, "", nil), true, nil
	}
	if callErr == nil && observeErr == nil {
		return cachePart(original.ID, "failed", "delete-incomplete", nil), true, nil
	}
	if cerrdefs.IsConflict(callErr) {
		return cachePart(original.ID, "skipped", "docker-conflict", callErr), true, nil
	}
	if cerrdefs.IsInvalidArgument(callErr) || cerrdefs.IsPermissionDenied(callErr) {
		return cachePart(original.ID, "failed", "docker-rejected", callErr), true, nil
	}
	return part, false, errors.Join(callErr, observeErr)
}
