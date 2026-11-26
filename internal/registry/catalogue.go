// SPDX-License-Identifier: Apache-2.0

package registry

import (
	"context"
	"errors"
	"strings"

	"github.com/jay94ks/mydcd/internal/registryclient"
	"github.com/jay94ks/mydcd/internal/schema"
	"github.com/jay94ks/mydcd/internal/storage"
)

type manifestPublication struct {
	Schema uint8
	Digest string
	At     uint64
}
type manifestCatalogueFact struct {
	Digest    string
	Published *manifestPublication `json:",omitempty"`
}

// Catalogue reads one atomic owner metadata view. It opens no second DB/root,
// takes no Raft authority and must be joined with the original owner close.
func (m *Metadata) Catalogue(ctx context.Context, authority, repo string, basis [32]byte, after string) (registryclient.CataloguePage, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.enter(ctx) != nil {
		return registryclient.CataloguePage{}, ErrStorage
	}
	if repo == "" {
		names, err := m.repositories(ctx)
		if err != nil {
			return registryclient.CataloguePage{}, err
		}
		page, selected, err := registryclient.CatalogueRange(authority, "", basis, names, nil, after)
		page.Repositories = selected
		page.UntaggedComplete = true
		return page, err
	}
	names, err := m.manifestReferences(ctx, repo)
	if err != nil {
		return registryclient.CataloguePage{}, err
	}
	id, err := repoID(repo)
	if err != nil {
		return registryclient.CataloguePage{}, err
	}
	facts := map[string]manifestCatalogueFact{}
	for _, ref := range names {
		raw, err := m.db.GetBounded(manifestPrefix+"ref/"+id+"/"+ref, 71)
		if err != nil {
			return registryclient.CataloguePage{}, ErrStorage
		}
		fact := manifestCatalogueFact{Digest: string(raw)}
		stamp, err := m.db.GetBounded(manifestPrefix+"published/"+id+"/"+ref, 1024)
		if err == nil {
			published, err := schema.Decode[manifestPublication](stamp)
			if err != nil || published.Schema != 1 || published.At == 0 || published.Digest != fact.Digest {
				return registryclient.CataloguePage{}, ErrStorage
			}
			fact.Published = &published
		} else if !errors.Is(err, storage.ErrMissing) {
			return registryclient.CataloguePage{}, ErrStorage
		}
		facts[ref] = fact
	}
	page, selected, err := registryclient.CatalogueRange(authority, repo, basis, names, facts, after)
	if err != nil {
		return page, err
	}
	page.UntaggedComplete = true
	for _, ref := range selected {
		if ctx.Err() != nil {
			return registryclient.CataloguePage{}, ctx.Err()
		}
		data, err := m.getManifest(ctx, repo, ref)
		if err != nil {
			return registryclient.CataloguePage{}, err
		}
		image, err := registryclient.DescribeManifest(authority, repo, ref, data.ContentType, data.Body, func(digest string) (string, []byte, error) {
			data, err := m.getManifest(ctx, repo, digest)
			return data.ContentType, data.Body, err
		})
		if err != nil {
			return registryclient.CataloguePage{}, err
		}
		if fact := facts[ref]; fact.Published != nil {
			image.UploadedAtKnown = true
			image.UploadedAt = fact.Published.At
		}
		if strings.HasPrefix(ref, "sha256:") && image.Digest != ref {
			return registryclient.CataloguePage{}, ErrStorage
		}
		page.Images = append(page.Images, image)
	}
	return page, nil
}
