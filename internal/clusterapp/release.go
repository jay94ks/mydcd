// SPDX-License-Identifier: Apache-2.0

package clusterapp

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"

	v1 "github.com/google/go-containerregistry/pkg/v1"
)

// The release manifest sits in a bundle directory next to the OCI layout
// files (devel/design/cluster-apps.md 3.3). ReleaseFile holds the manifest's
// JSON; SignatureFile holds the hex Ed25519 signature over its exact bytes.
const (
	ReleaseFile   = "sfc-release.json"
	SignatureFile = "sfc-release.sig"
)

// KeyDir holds the release keys this node trusts in addition to the built-in
// ones: one hex Ed25519 public key per *.pub file, added by root.
const KeyDir = "/etc/sfc/release-keys"

// maxReleaseFile bounds the manifest and signature files read from a bundle.
const maxReleaseFile = 64 << 10

// Release is a cluster app image's release manifest: which image a release
// key vouches for. sfcd runs only the image a trusted manifest names, so a
// new image needs a new signed manifest, not a new sfcd build.
type Release struct {
	Schema     int    `json:"schema"`
	App        string `json:"app"`        // Image.Name
	Repository string `json:"repository"` // Image.Repository
	Version    string `json:"version"`    // release that built it, e.g. 0.9.0
	Digest     string `json:"digest"`     // the image manifest digest, sha256:<hex>
}

// Hash is the manifest digest; valid only after check.
func (r Release) Hash() v1.Hash {
	h, _ := v1.NewHash(r.Digest)
	return h
}

func (r Release) check(i Image) error {
	h, err := v1.NewHash(r.Digest)
	if r.Schema != 1 || r.App != i.Name || r.Repository != i.Repository || r.Version == "" || len(r.Version) > 64 || err != nil || h.Algorithm != "sha256" {
		return ErrRelease
	}
	return nil
}

// Trust is the set of release keys a node accepts release manifests from.
type Trust struct{ keys []ed25519.PublicKey }

// releaseKeys are the release keys every sfcd build trusts, hex Ed25519
// public keys. The official release key goes here; its private half signs
// release manifests and never enters this repository.
var releaseKeys = []string{
	// Official release key (Jay 2026-11-27, X16). The private half is the
	// public repository's SFC_RELEASE_KEY Actions secret.
	"74217e280459642c3d18ff6bc66e1f09a04797681cbf4c39131bd6b1df55aa7c",
}

// LoadTrust returns the built-in release keys plus every *.pub key in dir. A
// missing dir adds none; a key file that does not parse is an error, so a
// mistyped key is not silently ignored.
func LoadTrust(dir string) (Trust, error) {
	var t Trust
	for _, k := range releaseKeys {
		pub, err := ParseKey([]byte(k))
		if err != nil {
			return Trust{}, fmt.Errorf("built-in release key: %w", err)
		}
		t.keys = append(t.keys, pub)
	}
	if dir == "" {
		return t, nil
	}
	names, err := filepath.Glob(filepath.Join(dir, "*.pub"))
	if err != nil {
		return Trust{}, err
	}
	sort.Strings(names)
	for _, name := range names {
		b, err := readSmall(name)
		if err != nil {
			return Trust{}, err
		}
		pub, err := ParseKey(b)
		if err != nil {
			return Trust{}, fmt.Errorf("release key %s: %w", name, err)
		}
		t.keys = append(t.keys, pub)
	}
	return t, nil
}

// BuiltinTrust is only the release keys built into sfcd.
func BuiltinTrust() (Trust, error) { return LoadTrust("") }

// TrustKeys builds a Trust from the given keys (tests, tools).
func TrustKeys(keys ...ed25519.PublicKey) Trust {
	return Trust{keys: append([]ed25519.PublicKey(nil), keys...)}
}

// Empty: no key is trusted, so no release manifest verifies.
func (t Trust) Empty() bool { return len(t.keys) == 0 }

// Verify reports whether sig is a signature of message by a trusted key.
// The release workflow signs SHA256SUMS with the same key
// (tools/clusterapp-bundle sign-file).
func (t Trust) Verify(message, sig []byte) bool { return t.verify(message, sig) }

func (t Trust) verify(message, sig []byte) bool {
	for _, k := range t.keys {
		if ed25519.Verify(k, message, sig) {
			return true
		}
	}
	return false
}

// ParseKey reads a hex Ed25519 public key (surrounding white space allowed).
func ParseKey(b []byte) (ed25519.PublicKey, error) {
	raw, err := hex.DecodeString(strings.TrimSpace(string(b)))
	if err != nil || len(raw) != ed25519.PublicKeySize {
		return nil, errors.New("not a hex Ed25519 public key")
	}
	return ed25519.PublicKey(raw), nil
}

// ReadRelease reads and verifies image i's release manifest in its bundle
// under dir. No bundle is ErrImageNotFound; a bundle whose manifest is
// unsigned, signed by no key in trust, or names another image is ErrRelease.
func ReadRelease(dir string, i Image, trust Trust) (Release, error) {
	if i.Layout == "" {
		return Release{}, ErrImageNotFound
	}
	bundle := filepath.Join(dir, i.Layout)
	if st, err := os.Stat(bundle); err != nil || !st.IsDir() {
		return Release{}, ErrImageNotFound
	}
	message, err := readSmall(filepath.Join(bundle, ReleaseFile))
	if errors.Is(err, fs.ErrNotExist) {
		return Release{}, ErrRelease
	} else if err != nil {
		return Release{}, err
	}
	sigText, err := readSmall(filepath.Join(bundle, SignatureFile))
	if errors.Is(err, fs.ErrNotExist) {
		return Release{}, ErrRelease
	} else if err != nil {
		return Release{}, err
	}
	sig, err := hex.DecodeString(strings.TrimSpace(string(sigText)))
	if err != nil || len(sig) != ed25519.SignatureSize || !trust.verify(message, sig) {
		return Release{}, ErrRelease
	}
	var r Release
	d := json.NewDecoder(bytes.NewReader(message))
	d.DisallowUnknownFields()
	if err := d.Decode(&r); err != nil || d.More() {
		return Release{}, ErrRelease
	}
	if err := r.check(i); err != nil {
		return Release{}, err
	}
	return r, nil
}

// SignRelease writes r's manifest and its signature with key into the bundle
// directory bundle (release tooling and tests).
func SignRelease(bundle string, r Release, key ed25519.PrivateKey) error {
	message, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return err
	}
	message = append(message, '\n')
	sig := hex.EncodeToString(ed25519.Sign(key, message)) + "\n"
	if err := os.WriteFile(filepath.Join(bundle, ReleaseFile), message, 0644); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(bundle, SignatureFile), []byte(sig), 0644)
}

func readSmall(name string) ([]byte, error) {
	f, err := os.Open(name)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	b := make([]byte, maxReleaseFile+1)
	n, err := f.Read(b)
	for err == nil && n <= maxReleaseFile {
		var m int
		m, err = f.Read(b[n:])
		n += m
	}
	if n > maxReleaseFile {
		return nil, fmt.Errorf("%s: larger than %d bytes", name, maxReleaseFile)
	}
	return b[:n], nil
}
