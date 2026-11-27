// SPDX-License-Identifier: Apache-2.0

// Package registryarchive writes and reads the images of a built-in registry
// as one OCI image layout in a tar file (oci-layout, index.json and
// blobs/sha256/...), for `sfcli registry export` and `import`
// (devel/design/cluster-backup-and-recovery.md, B6). Other tools (skopeo
// oci-archive:, crane) read the same file.
//
// The archive holds only image content. Access to a registry is a scoped
// short-lived credential per repository (Remote); nothing secret is written.
package registryarchive

import (
	"errors"
	"fmt"
	"strings"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/types"
)

// Annotations on the index.json entries. RefName is the OCI tag annotation;
// Repository keeps the repository path so one archive can hold several
// repositories. A file without Repository needs a repository given on import.
const (
	RefName    = "org.opencontainers.image.ref.name"
	Repository = "io.sfc.repository"

	layoutFile    = "oci-layout"
	indexFile     = "index.json"
	layoutVersion = `{"imageLayoutVersion":"1.0.0"}`

	// MaxManifestBytes bounds one manifest or index read into memory.
	MaxManifestBytes = 4 << 20
	// MaxEntries bounds the tagged images of one archive.
	MaxEntries = 4096
	// maxChildren bounds the manifests of one index.
	maxChildren = 256
)

// ErrArchive is a file that is not an OCI layout this package accepts.
var ErrArchive = errors.New("not an OCI image layout archive")

// Entry is one tagged image: the root manifest (an image or an index).
type Entry struct {
	Repository, Tag, Digest string
	MediaType               types.MediaType
	Size                    int64
}

func (e Entry) String() string { return e.Repository + ":" + e.Tag }

// Remote opens one repository of the registry for reading (push false) or
// writing. The returned options carry the transport and the credential.
type Remote func(repository string, push bool) (name.Repository, []remote.Option, error)

// ValidTag reports a tag the distribution API accepts.
func ValidTag(tag string) bool {
	if tag == "" || len(tag) > 128 {
		return false
	}
	for i, r := range tag {
		ok := r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '_' || i > 0 && (r == '.' || r == '-')
		if !ok {
			return false
		}
	}
	return true
}

// ValidRepository reports a repository path (lower case components).
func ValidRepository(repo string) bool {
	if repo == "" || len(repo) > 255 || strings.HasPrefix(repo, "/") || strings.HasSuffix(repo, "/") {
		return false
	}
	_, err := name.NewRepository("registry.invalid/"+repo, name.StrictValidation)
	return err == nil
}

func manifestType(mt types.MediaType) (index, ok bool) {
	switch mt {
	case types.OCIImageIndex, types.DockerManifestList:
		return true, true
	case types.OCIManifestSchema1, types.DockerManifestSchema2:
		return false, true
	}
	return false, false
}

func blobPath(hex string) string { return "blobs/sha256/" + hex }

func digestHex(digest string) (string, error) {
	hex, ok := strings.CutPrefix(digest, "sha256:")
	if !ok || len(hex) != 64 || strings.Trim(hex, "0123456789abcdef") != "" {
		return "", fmt.Errorf("%w: digest %q is not sha256", ErrArchive, digest)
	}
	return hex, nil
}
