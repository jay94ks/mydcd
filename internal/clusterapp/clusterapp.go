// SPDX-License-Identifier: Apache-2.0

// Package clusterapp lists the cluster app images: container images that ship
// with sfc. A cluster app image that sfcd runs is a cluster app
// (devel/design/cluster-apps.md). Each one has its own control policy.
package clusterapp

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/layout"
)

// Control says who may bring a cluster app up or down.
type Control int

const (
	// NodeConfigOnly: only the node's node.yaml brings it up or down, read
	// when sfcd starts. No CLI, web or API action exists for it.
	NodeConfigOnly Control = iota + 1
)

// Image is one cluster app image.
type Image struct {
	Name    string
	Control Control
	// Layout is the image's bundle directory under the image directory: an
	// OCI layout plus its signed release manifest (ReleaseFile, SignatureFile).
	Layout string
	// Repository names the image for people (sfc/web). The release
	// manifest must name the same one.
	Repository string
	// Ports are the ports the cluster app listens on inside its container.
	Ports []Port
}

// Port is one listening port of a cluster app.
type Port struct {
	Name     string // web, acme
	Port     uint16
	Protocol string // tcp
}

// ImageDirs are where the release that exe (sfcd's own executable) came from
// installs cluster app image bundles, nearest first
// (devel/design/install-packages.md 4). The packages and the archive keep the
// real sfcd in <prefix>/lib/sfc/bin, so its bundles are in the sibling
// <prefix>/lib/sfc/images: /usr/lib/sfc/images for a deb or rpm,
// /usr/local/lib/sfc/images for the archive. An sfcd placed straight in
// <prefix>/bin finds <prefix>/lib/sfc/images. Symlinks in exe are resolved
// first, so /usr/bin/sfcd finds the bundles of /usr/lib/sfc/bin/sfcd.
func ImageDirs(exe string) []string {
	if real, err := filepath.EvalSymlinks(exe); err == nil {
		exe = real
	}
	bin := filepath.Dir(exe)
	return []string{
		filepath.Clean(filepath.Join(bin, "..", "images")),
		filepath.Clean(filepath.Join(bin, "..", "lib", "sfc", "images")),
	}
}

// FindImageDir returns the first of dirs that holds image i's bundle. When
// none does, the error is ErrImageNotFound and names every place it looked.
func FindImageDir(dirs []string, i Image) (string, error) {
	tried := make([]string, 0, len(dirs))
	for _, dir := range dirs {
		bundle := filepath.Join(dir, i.Layout)
		if i.Layout != "" {
			if st, err := os.Stat(bundle); err == nil && st.IsDir() {
				return dir, nil
			}
		}
		tried = append(tried, bundle)
	}
	return "", fmt.Errorf("%w (looked in %s)", ErrImageNotFound, strings.Join(tried, ", "))
}

// InstalledImageDir is FindImageDir over the ImageDirs of the running
// executable.
func InstalledImageDir(i Image) (string, error) {
	exe, err := os.Executable()
	if err != nil {
		return "", errors.Join(ErrImageNotFound, err)
	}
	return FindImageDir(ImageDirs(exe), i)
}

// ErrImageNotFound: the cluster app image is not installed on this node. The
// node daemon package ships each cluster app image as an optional package, so a
// node may have none.
var ErrImageNotFound = errors.New("cluster app image not found")

// ErrRelease: the bundle's release manifest is missing its signature, is not
// signed by a trusted release key, or does not describe this image.
var ErrRelease = errors.New("cluster app release manifest is not signed by a trusted key")

// ErrImage: the bundle does not hold the image its release manifest names
// intact.
var ErrImage = errors.New("cluster app image does not match its release manifest")

// Bundle is a verified cluster app image: the image and the signed release
// manifest that named it.
type Bundle struct {
	Image   v1.Image
	Release Release
}

// Open reads the image's release manifest from its bundle in dir, checks it is
// signed by a key in trust, and returns the image that manifest names. The
// Engine pulls it by PullRef while a ticket serves it through Bundle.Open.
func Open(dir string, i Image, trust Trust) (Bundle, error) {
	r, err := ReadRelease(dir, i, trust)
	if err != nil {
		return Bundle{}, err
	}
	pin := r.Hash()
	p, err := layout.FromPath(filepath.Join(dir, i.Layout))
	if err != nil || !listed(p, pin) {
		return Bundle{}, ErrImage
	}
	img, err := p.Image(pin)
	if err != nil {
		return Bundle{}, ErrImage
	}
	if got, err := img.Digest(); err != nil || got != pin {
		return Bundle{}, ErrImage
	}
	return Bundle{Image: img, Release: r}, nil
}

// listed: the bundle's index names the manifest.
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

// DefaultUID is the non-root UID a cluster app container runs as unless
// node.yaml sets another. Its management socket and data are owned by it.
const DefaultUID = 10001

// ContainerRunDir is where a cluster app container sees its run directory, so
// its management socket is ContainerRunDir/sfcdp.sock.
const ContainerRunDir = "/run/sfc"

// socketName is the management socket's file name in a run directory.
const socketName = "sfcdp.sock"

// RunDir is the host directory that holds cluster app name's own management
// socket: state_dir/cluster-apps/<name>/run. Only this directory is bound into
// the container (at ContainerRunDir); never its parents or the host socket.
func RunDir(stateDir, name string) string {
	return filepath.Join(stateDir, "cluster-apps", name, "run")
}

// SocketPath is cluster app name's management socket on the host.
func SocketPath(stateDir, name string) string {
	return filepath.Join(RunDir(stateDir, name), socketName)
}

// Web is sfc-web, the web management UI.
const Web = "web"

// WebPort and WebACMEPort are sfc-web's listeners: the web UI and the ACME
// HTTP-01 responder.
const (
	WebPort     uint16 = 8080
	WebACMEPort uint16 = 8081
	// WebDirectPort is the listener sfcd's node.yaml port forwards to; it
	// trusts no X-Forwarded-* header, since the forwarder connects from the
	// pool gateway that the main listener trusts as ingress.
	WebDirectPort uint16 = 8082
)

var images = []Image{{Name: Web, Control: NodeConfigOnly, Layout: "sfc-web", Repository: "sfc/web", Ports: []Port{{Name: "web", Port: WebPort, Protocol: "tcp"}, {Name: "acme", Port: WebACMEPort, Protocol: "tcp"}, {Name: "direct", Port: WebDirectPort, Protocol: "tcp"}}}}

// Lookup returns the cluster app image of that name.
func Lookup(name string) (Image, bool) {
	for _, i := range images {
		if i.Name == name {
			i.Ports = append([]Port(nil), i.Ports...)
			return i, true
		}
	}
	return Image{}, false
}

// Images lists every cluster app image.
func Images() []Image { return append([]Image(nil), images...) }
