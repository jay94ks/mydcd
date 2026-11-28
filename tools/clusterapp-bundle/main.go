// SPDX-License-Identifier: Apache-2.0

// Command clusterapp-bundle makes release keys and signs cluster app image
// bundles (devel/design/cluster-apps.md 3.3).
//
//	go run ./tools/clusterapp-bundle keygen -out release.key
//	go run ./tools/clusterapp-bundle sign -key release.key -app web -version 0.9.1 -bundle dist/images/sfc-web
//	go run ./tools/clusterapp-bundle verify -pub release.pub -app web -bundle dist/images/sfc-web
//	go run ./tools/clusterapp-bundle verify -builtin -app web -bundle dist/images/sfc-web
//	go run ./tools/clusterapp-bundle sign-file -key-env SFC_RELEASE_KEY -file dist/SHA256SUMS
//	go run ./tools/clusterapp-bundle verify-file -builtin -file dist/SHA256SUMS
//
// keygen writes the private key (hex Ed25519 seed, mode 0600) to -out and
// its public key to -out with .pub in place of .key. The public key goes into
// sfcd's built-in release keys, or onto a node as /etc/sfc/release-keys/*.pub.
// sign reads the key from -key, or from the environment variable that
// -key-env names (the release workflow's secret). verify -builtin checks
// against the keys built into sfcd, so a release signed with a key sfcd does
// not trust fails before it is published.
// sign writes sfc-release.json and sfc-release.sig into an OCI layout
// directory that holds exactly one image manifest.
// sign-file signs any file (the release's SHA256SUMS) with the same key and
// writes the hex Ed25519 signature of its exact bytes to <file>.sig, the
// format of sfc-release.sig (devel/design/install-packages.md 7).
package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/google/go-containerregistry/pkg/v1/layout"
	"github.com/jay94ks/seafield/internal/clusterapp"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: clusterapp-bundle keygen|sign|verify|sign-file|verify-file [flags]")
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "keygen":
		err = keygen(os.Args[2:])
	case "sign":
		err = sign(os.Args[2:])
	case "verify":
		err = verify(os.Args[2:])
	case "sign-file":
		err = signFile(os.Args[2:])
	case "verify-file":
		err = verifyFile(os.Args[2:])
	default:
		err = fmt.Errorf("unknown command %q", os.Args[1])
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "clusterapp-bundle:", err)
		os.Exit(1)
	}
}

func keygen(args []string) error {
	fs := flag.NewFlagSet("keygen", flag.ExitOnError)
	out := fs.String("out", "", "private key file to create (*.key)")
	_ = fs.Parse(args)
	if !strings.HasSuffix(*out, ".key") {
		return errors.New("-out must name a new *.key file")
	}
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	f, err := os.OpenFile(*out, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	if _, err = f.WriteString(hex.EncodeToString(key.Seed()) + "\n"); err != nil {
		f.Close()
		return err
	}
	if err = f.Close(); err != nil {
		return err
	}
	pubFile := strings.TrimSuffix(*out, ".key") + ".pub"
	if err = os.WriteFile(pubFile, []byte(hex.EncodeToString(pub)+"\n"), 0644); err != nil {
		return err
	}
	fmt.Println(hex.EncodeToString(pub))
	return nil
}

func sign(args []string) error {
	fs := flag.NewFlagSet("sign", flag.ExitOnError)
	keyFile := fs.String("key", "", "private key file from keygen")
	keyEnv := fs.String("key-env", "", "environment variable holding the private key instead of -key")
	app := fs.String("app", "", "cluster app image name (web)")
	version := fs.String("version", "", "release version (0.9.1)")
	bundle := fs.String("bundle", "", "OCI layout directory of the image")
	_ = fs.Parse(args)
	image, ok := clusterapp.Lookup(*app)
	if !ok {
		return fmt.Errorf("unknown cluster app image %q", *app)
	}
	seed, err := readSeed(*keyFile, *keyEnv)
	if err != nil {
		return err
	}
	p, err := layout.FromPath(*bundle)
	if err != nil {
		return err
	}
	index, err := p.ImageIndex()
	if err != nil {
		return err
	}
	m, err := index.IndexManifest()
	if err != nil {
		return err
	}
	if len(m.Manifests) != 1 || !m.Manifests[0].MediaType.IsImage() {
		return errors.New("-bundle must hold exactly one image manifest (one platform)")
	}
	r := clusterapp.Release{Schema: 1, App: image.Name, Repository: image.Repository, Version: *version, Digest: m.Manifests[0].Digest.String()}
	if err = clusterapp.SignRelease(*bundle, r, ed25519.NewKeyFromSeed(seed)); err != nil {
		return err
	}
	pub := ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey)
	if _, err = clusterapp.Open(filepath.Dir(*bundle), withLayout(image, *bundle), clusterapp.TrustKeys(pub)); err != nil {
		return fmt.Errorf("signed bundle does not verify: %w", err)
	}
	fmt.Println(r.Digest)
	return nil
}

func verify(args []string) error {
	fs := flag.NewFlagSet("verify", flag.ExitOnError)
	pubFile := fs.String("pub", "", "public key file (*.pub)")
	builtin := fs.Bool("builtin", false, "verify against sfcd's built-in release keys instead of -pub")
	app := fs.String("app", "", "cluster app image name (web)")
	bundle := fs.String("bundle", "", "OCI layout directory of the image")
	_ = fs.Parse(args)
	image, ok := clusterapp.Lookup(*app)
	if !ok {
		return fmt.Errorf("unknown cluster app image %q", *app)
	}
	trust, err := readTrust(*pubFile, *builtin)
	if err != nil {
		return err
	}
	got, err := clusterapp.Open(filepath.Dir(*bundle), withLayout(image, *bundle), trust)
	if err != nil {
		return err
	}
	fmt.Println(got.Release.Version, got.Release.Digest)
	return nil
}

// withLayout points image at bundle, whatever its directory is named.
func withLayout(image clusterapp.Image, bundle string) clusterapp.Image {
	image.Layout = filepath.Base(filepath.Clean(bundle))
	return image
}

// signFile writes <file>.sig: the hex Ed25519 signature of file's bytes.
func signFile(args []string) error {
	fs := flag.NewFlagSet("sign-file", flag.ExitOnError)
	keyFile := fs.String("key", "", "private key file from keygen")
	keyEnv := fs.String("key-env", "", "environment variable holding the private key instead of -key")
	file := fs.String("file", "", "file to sign (SHA256SUMS)")
	_ = fs.Parse(args)
	seed, err := readSeed(*keyFile, *keyEnv)
	if err != nil {
		return err
	}
	message, err := os.ReadFile(*file)
	if err != nil {
		return err
	}
	key := ed25519.NewKeyFromSeed(seed)
	sig := ed25519.Sign(key, message)
	if !ed25519.Verify(key.Public().(ed25519.PublicKey), message, sig) {
		return errors.New("signature does not verify")
	}
	return os.WriteFile(*file+".sig", []byte(hex.EncodeToString(sig)+"\n"), 0644)
}

// verifyFile checks <file>.sig against -pub or the built-in release keys.
func verifyFile(args []string) error {
	fs := flag.NewFlagSet("verify-file", flag.ExitOnError)
	pubFile := fs.String("pub", "", "public key file (*.pub)")
	builtin := fs.Bool("builtin", false, "verify against sfcd's built-in release keys instead of -pub")
	file := fs.String("file", "", "signed file (SHA256SUMS); the signature is <file>.sig")
	_ = fs.Parse(args)
	trust, err := readTrust(*pubFile, *builtin)
	if err != nil {
		return err
	}
	message, err := os.ReadFile(*file)
	if err != nil {
		return err
	}
	text, err := os.ReadFile(*file + ".sig")
	if err != nil {
		return err
	}
	sig, err := hex.DecodeString(strings.TrimSpace(string(text)))
	if err != nil || len(sig) != ed25519.SignatureSize || !trust.Verify(message, sig) {
		return fmt.Errorf("%s.sig is not a signature of %s by a trusted key", *file, *file)
	}
	fmt.Println("OK", *file)
	return nil
}

// readSeed reads a keygen private key from keyFile or from the environment
// variable keyEnv (exactly one of them).
func readSeed(keyFile, keyEnv string) ([]byte, error) {
	var b []byte
	var err error
	switch {
	case keyEnv != "" && keyFile == "":
		b = []byte(os.Getenv(keyEnv))
		if len(b) == 0 {
			return nil, fmt.Errorf("environment variable %s is empty", keyEnv)
		}
	case keyFile != "" && keyEnv == "":
		if b, err = os.ReadFile(keyFile); err != nil {
			return nil, err
		}
	default:
		return nil, errors.New("give exactly one of -key and -key-env")
	}
	seed, err := hex.DecodeString(strings.TrimSpace(string(b)))
	if err != nil || len(seed) != ed25519.SeedSize {
		return nil, errors.New("-key is not a key from keygen")
	}
	return seed, nil
}

// readTrust is the key in pubFile, or sfcd's built-in release keys.
func readTrust(pubFile string, builtin bool) (clusterapp.Trust, error) {
	switch {
	case builtin && pubFile == "":
		trust, err := clusterapp.BuiltinTrust()
		if err != nil {
			return clusterapp.Trust{}, err
		}
		if trust.Empty() {
			return clusterapp.Trust{}, errors.New("this sfcd has no built-in release key (internal/clusterapp/release.go releaseKeys)")
		}
		return trust, nil
	case pubFile != "" && !builtin:
		b, err := os.ReadFile(pubFile)
		if err != nil {
			return clusterapp.Trust{}, err
		}
		pub, err := clusterapp.ParseKey(b)
		if err != nil {
			return clusterapp.Trust{}, err
		}
		return clusterapp.TrustKeys(pub), nil
	default:
		return clusterapp.Trust{}, errors.New("give exactly one of -pub and -builtin")
	}
}
