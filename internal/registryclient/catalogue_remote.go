// SPDX-License-Identifier: Apache-2.0

package registryclient

import (
	"context"
	"strings"

	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"
)

// Catalogue uses the pinned SDK's authenticated, same-host pagination and this
// client's metadata byte/credential boundaries. Standard OCI enumeration only
// returns tags: it cannot claim to enumerate external untagged manifests or
// know a server's upload time from the image config's Created timestamp.
func (a *Access) Catalogue(ctx context.Context, repository string, basis [32]byte, after string, allow func(string) bool) (CataloguePage, error) {
	if allow == nil {
		return CataloguePage{}, &Error{Code: "DENIED"}
	}
	a.auth.mu.Lock()
	closed := a.auth.closed
	a.auth.mu.Unlock()
	if closed {
		return CataloguePage{}, &Error{Code: "CLOSED"}
	}
	names, err := a.catalogueNames(ctx, repository, allow)
	if err != nil {
		return CataloguePage{}, err
	}
	page, selected, err := CatalogueRange(a.authority, repository, basis, names, nil, after)
	if err != nil {
		return page, err
	}
	page.Live = true
	if repository == "" {
		page.Repositories = selected
		return page, nil
	}
	for _, tag := range selected {
		if strings.Contains(tag, ":") {
			return CataloguePage{}, &Error{Code: "INVALID_IMAGE"}
		}
		ref := a.authority + "/" + repository + ":" + tag
		resolution, raw, err := a.manifest(ctx, ref)
		if err != nil {
			return CataloguePage{}, err
		}
		image, err := DescribeManifest(a.authority, repository, tag, resolution.MediaType, raw, func(digest string) (string, []byte, error) {
			resolution, raw, err := a.manifest(ctx, a.authority+"/"+repository+"@"+digest)
			return resolution.MediaType, raw, err
		})
		if err != nil {
			return CataloguePage{}, err
		}
		page.Images = append(page.Images, image)
	}
	return page, nil
}

func (a *Access) catalogueNames(ctx context.Context, repository string, allow func(string) bool) ([]string, error) {
	if allow == nil {
		return nil, &Error{Code: "DENIED"}
	}
	a.auth.mu.Lock()
	closed := a.auth.closed
	a.auth.mu.Unlock()
	if closed {
		return nil, &Error{Code: "CLOSED"}
	}
	options := append(a.options(ctx, v1.Platform{}), remote.WithPageSize(256))
	puller, err := remote.NewPuller(options...)
	if err != nil {
		return nil, Sanitize(err)
	}
	names := []string{}
	count, total := 0, 0
	accept := func(values []string) error {
		count += len(values)
		if count > MaxCatalogueNames {
			return &Error{Code: "METADATA_BUDGET"}
		}
		for _, value := range values {
			total += len(value)
			if total > 1<<20 || value == "" || len(value) > 255 {
				return &Error{Code: "METADATA_BUDGET"}
			}
			names = append(names, value)
		}
		return nil
	}
	if repository == "" {
		reg, err := name.NewRegistry(a.authority, name.StrictValidation)
		if err != nil {
			return nil, &Error{Code: "INVALID_SOURCE"}
		}
		pages, err := puller.Catalogger(ctx, reg)
		if err != nil {
			return nil, Sanitize(err)
		}
		for loops := 0; pages.HasNext(); loops++ {
			if loops >= 256 {
				return nil, &Error{Code: "METADATA_BUDGET"}
			}
			page, err := pages.Next(ctx)
			if err != nil {
				return nil, Sanitize(err)
			}
			if err = accept(page.Repos); err != nil {
				return nil, err
			}
		}
		filtered := names[:0]
		for _, repo := range names {
			if allow(repo) {
				filtered = append(filtered, repo)
			}
		}
		names = filtered
	} else {
		if !allow(repository) {
			return nil, &Error{Code: "DENIED"}
		}
		repo, err := name.NewRepository(a.authority+"/"+repository, name.StrictValidation)
		if err != nil || repo.RepositoryStr() != repository {
			return nil, &Error{Code: "INVALID_IMAGE"}
		}
		pages, err := puller.Lister(ctx, repo)
		if err != nil {
			return nil, Sanitize(err)
		}
		for loops := 0; pages.HasNext(); loops++ {
			if loops >= 256 {
				return nil, &Error{Code: "METADATA_BUDGET"}
			}
			page, err := pages.Next(ctx)
			if err != nil {
				return nil, Sanitize(err)
			}
			if page.Name != repository {
				return nil, &Error{Code: "INVALID_IMAGE"}
			}
			if err = accept(page.Tags); err != nil {
				return nil, err
			}
		}
	}
	return names, nil
}
