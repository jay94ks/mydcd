// SPDX-License-Identifier: Apache-2.0

// Package nodeapp lists the node app images: container images that ship
// with mydc. A node app image that mydcd runs is a node app
// (devel/design/node-apps.md). Each one has its own control policy.
package nodeapp

import (
	"errors"
	"path/filepath"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/layout"
)

// Control says who may bring a node app up or down.
type Control int

const (
	// NodeConfigOnly: only the node's node.yaml brings it up or down, read
	// when mydcd starts. No CLI, web or API action exists for it.
	NodeConfigOnly Control = iota + 1
)

// Image is one node app image.
type Image struct {
	Name    string
	Control Control
	// Layout is the image's OCI layout directory under the image directory.
	Layout string
	digest *string
}

// ImageDir is where a release installs node app image bundles.
const ImageDir = "/usr/local/lib/mydc/images"

// webDigest pins mydc-web's manifest digest. A release sets it:
// -ldflags "-X github.com/jay94ks/mydcd/internal/nodeapp.webDigest=sha256:<hex>". A build
// without it has no usable web image.
var webDigest string

// ErrImageNotFound: the node app image is not installed on this node. The
// node daemon package ships each node app image as an optional package, so a
// node may have none; a build without the pin ships none either.
var ErrImageNotFound = errors.New("node app image not found")

// ErrImage: the installed bundle does not hold the pinned image intact.
var ErrImage = errors.New("node app image does not match its pinned digest")

// Digest is the pinned manifest digest.
func (i Image) Digest() (v1.Hash, bool) {
	if i.digest == nil || *i.digest == "" {
		return v1.Hash{}, false
	}
	h, err := v1.NewHash(*i.digest)
	return h, err == nil && h.Algorithm == "sha256"
}

// Open reads the image from its bundle in dir and checks it is the pinned
// one. Loading it into the Engine is engine.Client.LoadImage.
func Open(dir string, i Image) (v1.Image, error) {
	pin, ok := i.Digest()
	if !ok || i.Layout == "" {
		return nil, ErrImageNotFound
	}
	p, err := layout.FromPath(filepath.Join(dir, i.Layout))
	if err != nil {
		return nil, ErrImageNotFound
	}
	if !listed(p, pin) {
		return nil, ErrImageNotFound
	}
	img, err := p.Image(pin)
	if err != nil {
		return nil, ErrImage
	}
	if got, err := img.Digest(); err != nil || got != pin {
		return nil, ErrImage
	}
	return img, nil
}

// listed: the bundle's index names the pinned manifest.
func listed(p layout.Path, pin v1.Hash) bool {
	index, err := p.ImageIndex()
	if err != nil {
		return false
	}
	m, err := index.IndexManifest()
	if err != nil {
		return false
	}
	for _, d := range m.Manifests {
		if d.Digest == pin {
			return true
		}
	}
	return false
}

// Web is mydc-web, the web management UI.
const Web = "web"

var images = []Image{{Name: Web, Control: NodeConfigOnly, Layout: "mydc-web", digest: &webDigest}}

// Lookup returns the node app image of that name.
func Lookup(name string) (Image, bool) {
	for _, i := range images {
		if i.Name == name {
			return i, true
		}
	}
	return Image{}, false
}

// Images lists every node app image.
func Images() []Image { return append([]Image(nil), images...) }
