// SPDX-License-Identifier: Apache-2.0

package clusterapp

import (
	"bytes"
	"context"
	"io"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/jay94ks/seafield/internal/registryclient"
)

// Repository is the reserved repository the engine pulls a cluster app's
// image from (purpose 37). It has no registry host, so it is never a
// tenant registry's repository, and the engine sends it exactly as written.
func Repository(app string) string { return "sfc-cluster-app/" + app }

// PullRef is the pull reference of b's image: the repository and the digest
// its signed release manifest names.
func (b Bundle) PullRef(app string) string { return Repository(app) + "@" + b.Release.Digest }

// Open reads one item of b's image for the engine's pull (an
// engineimage.Opener): its manifest, its config or one of its layers, from
// offset. The bundle was verified when it was opened; the engine checks the
// digest of what it receives.
func (b Bundle) Open(_ context.Context, q registryclient.GraphContentQuery, offset int64) (registryclient.ContentInfo, io.ReadCloser, error) {
	info := registryclient.ContentInfo{Schema: 1, Ref: q.Selected().Ref, Kind: q.Kind}
	if offset < 0 || b.Image == nil {
		return info, nil, ErrImage
	}
	var raw []byte
	var rc io.ReadCloser
	var err error
	switch q.Kind {
	case "manifest":
		if len(q.Path) != 0 {
			return info, nil, ErrImage
		}
		raw, err = b.Image.RawManifest()
		if err == nil {
			media, merr := b.Image.MediaType()
			info.MediaType, err = string(media), merr
		}
		info.Digest = b.Release.Digest
	case "config":
		raw, err = b.Image.RawConfigFile()
		if err == nil {
			m, merr := b.Image.Manifest()
			if err = merr; err == nil {
				if m.Config.Digest.String() != q.Digest {
					return info, nil, ErrImage
				}
				info.MediaType, info.Digest = string(m.Config.MediaType), q.Digest
			}
		}
	case "layer":
		m, merr := b.Image.Manifest()
		if merr != nil {
			return info, nil, merr
		}
		var layer v1.Layer
		for _, l := range m.Layers {
			if l.Digest.String() == q.Digest && layer == nil {
				info.MediaType, info.Digest, info.Bytes = string(l.MediaType), q.Digest, l.Size
				if layer, err = b.Image.LayerByDigest(l.Digest); err != nil {
					return info, nil, err
				}
			}
		}
		if layer == nil {
			return info, nil, ErrImage
		}
		if rc, err = layer.Compressed(); err != nil {
			return info, nil, err
		}
		if offset > info.Bytes {
			rc.Close()
			return info, nil, ErrImage
		}
		if _, err = io.CopyN(io.Discard, rc, offset); err != nil {
			rc.Close()
			return info, nil, err
		}
		return info, rc, nil
	default:
		return info, nil, ErrImage
	}
	if err != nil {
		return info, nil, err
	}
	info.Bytes = int64(len(raw))
	if offset > info.Bytes {
		return info, nil, ErrImage
	}
	return info, io.NopCloser(bytes.NewReader(raw[offset:])), nil
}
