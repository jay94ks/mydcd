// SPDX-License-Identifier: Apache-2.0

// Package enginefixture supplies a real, locally imported static test image.
// It is used by integration tests only, never by product packages.
package enginefixture

import (
	"archive/tar"
	"context"
	"debug/elf"
	"encoding/json"
	"github.com/jay94ks/mydcd/internal/engine"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"testing"
	"time"

	cerrdefs "github.com/containerd/errdefs"
	"github.com/moby/moby/client"
)

type Fixture struct {
	Client          *engine.Client
	Image, ImageRef string
}

func Open(t *testing.T, ctx context.Context, owner, tag string) *Fixture {
	return OpenConfigured(t, ctx, owner, tag, nil)
}

// OpenConfigured imports the same local static image with explicit image
// metadata. Changes are test inputs; ownership labeling remains fixture-owned.
func OpenConfigured(t *testing.T, ctx context.Context, owner, tag string, changes []string, files ...map[string][]byte) *Fixture {
	if len(files) > 1 {
		t.Fatal("at most one explicit fixture file set")
	}
	var extra map[string][]byte
	if len(files) == 1 {
		extra = files[0]
	}
	return open(t, ctx, owner, tag, changes, "", extra)
}

// OpenPrepared imports a user-built static fixture when the test binary itself
// needs root directory permissions. It never invokes Go under root.
func OpenPrepared(t *testing.T, ctx context.Context, owner, tag string, changes []string, binary string, files ...map[string][]byte) *Fixture {
	if binary == "" || !filepath.IsAbs(binary) {
		t.Fatal("explicit prebuilt backend required")
	}
	if len(files) > 1 {
		t.Fatal("at most one explicit fixture file set")
	}
	var extra map[string][]byte
	if len(files) == 1 {
		extra = files[0]
	}
	return open(t, ctx, owner, tag, changes, binary, extra)
}
func open(t *testing.T, ctx context.Context, owner, tag string, changes []string, binary string, files map[string][]byte) *Fixture {
	t.Helper()
	c, err := engine.Open(ctx, "unix:///var/run/docker.sock", owner)
	if err != nil {
		t.Fatal(err)
	}
	f := &Fixture{Client: c, ImageRef: "mydc-boundary/" + tag + ":local"}
	t.Cleanup(func() {
		if err := c.Close(); err != nil {
			t.Error(err)
		}
	})
	if _, err = c.API.ImageInspect(ctx, f.ImageRef); !cerrdefs.IsNotFound(err) {
		t.Fatal("fixture image must be initially absent", err)
	}
	beforeImport := func() {
		// Cleanup precedes import and product mutation. It uses the exact test owner
		// and native full IDs, and is independent of the failed request's context.
		t.Cleanup(func() {
			clean, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			filters := client.Filters{}.Add("label", "org.mydc.owner="+owner)
			containers, e := c.API.ContainerList(clean, client.ContainerListOptions{All: true, Filters: filters})
			if e != nil {
				t.Error("rollback list containers", e)
			}
			for _, item := range containers.Items {
				if item.Labels["org.mydc.owner"] != owner || item.Labels["org.mydc.kind"] != "container" {
					t.Error("rollback ownership mismatch")
					continue
				}
				if !t.Failed() {
					t.Error("product retained a test container", item.ID)
				}
				if _, e = c.API.ContainerRemove(clean, item.ID, client.ContainerRemoveOptions{Force: true, RemoveVolumes: true}); e != nil {
					t.Error("rollback container", e)
				}
			}
			networks, e := c.API.NetworkList(clean, client.NetworkListOptions{Filters: filters})
			if e != nil {
				t.Error("rollback list networks", e)
			}
			for _, item := range networks.Items {
				if item.Labels["org.mydc.owner"] != owner || item.Labels["org.mydc.kind"] != "bridge" {
					t.Error("rollback network ownership mismatch")
					continue
				}
				if !t.Failed() {
					t.Error("product retained a test bridge", item.ID)
				}
				if _, e = c.API.NetworkRemove(clean, item.ID, client.NetworkRemoveOptions{}); e != nil {
					t.Error("rollback bridge", e)
				}
			}
			image, e := c.API.ImageInspect(clean, f.ImageRef)
			if e == nil {
				if image.Config == nil || image.Config.Labels["org.mydc.test.owner"] != tag {
					t.Error("rollback image ownership mismatch")
				} else if _, e = c.API.ImageRemove(clean, f.ImageRef, client.ImageRemoveOptions{}); e != nil {
					t.Error("rollback image", e)
				}
			} else if !cerrdefs.IsNotFound(e) {
				t.Error("rollback image inspect", e)
			}
			containers, e = c.API.ContainerList(clean, client.ContainerListOptions{All: true, Filters: filters})
			if e != nil || len(containers.Items) != 0 {
				t.Error("rollback containers remain", e)
			}
			networks, e = c.API.NetworkList(clean, client.NetworkListOptions{Filters: filters})
			if e != nil || len(networks.Items) != 0 {
				t.Error("rollback networks remain", e)
			}
			if _, e = c.API.ImageInspect(clean, f.ImageRef); !cerrdefs.IsNotFound(e) {
				t.Error("rollback image remains", e)
			}
		})
	}
	return importLocalImage(t, ctx, f, tag, changes, binary, files, beforeImport)
}

// ImportPrepared shares the exact static-image import implementation without
// owning the caller's Engine connection, containers, networks or cleanup.
// The caller registers exact rollback BEFORE invoking this function.
func ImportPrepared(t *testing.T, ctx context.Context, c *engine.Client, tag, binary string, changes []string) *Fixture {
	t.Helper()
	if c == nil || c.API == nil || c.Owner == "" || binary == "" || !filepath.IsAbs(binary) {
		t.Fatal("explicit caller-owned Engine and prebuilt backend required")
	}
	f := &Fixture{Client: c, ImageRef: "mydc-boundary/" + tag + ":local"}
	if _, err := c.API.ImageInspect(ctx, f.ImageRef); !cerrdefs.IsNotFound(err) {
		t.Fatal("prepared image must initially be absent", err)
	}
	return importLocalImage(t, ctx, f, tag, changes, binary, nil, nil)
}

func importLocalImage(t *testing.T, ctx context.Context, f *Fixture, tag string, changes []string, binary string, files map[string][]byte, beforeImport func()) *Fixture {
	t.Helper()
	c := f.Client
	owner := c.Owner
	root := t.TempDir()
	_, file, _, _ := runtime.Caller(0)
	workspace := filepath.Clean(filepath.Join(filepath.Dir(file), "../.."))
	if binary == "" {
		binary = filepath.Join(root, "backend")
		build := exec.CommandContext(ctx, "go", "build", "-p", "2", "-o", binary, "./apps/dockerbackend")
		build.Dir = workspace
		build.Env = append(os.Environ(), "CGO_ENABLED=0")
		if out, err := build.CombinedOutput(); err != nil {
			t.Fatalf("fixture build: %v %s", err, out)
		}
	}
	executable, err := elf.Open(binary)
	if err != nil {
		t.Fatal("fixture backend must be a static Linux ELF", err)
	}
	for _, program := range executable.Progs {
		if program.Type == elf.PT_INTERP {
			executable.Close()
			t.Fatal("fixture backend requires a dynamic loader; build it with CGO_ENABLED=0 before importing the scratch image")
		}
	}
	if err := executable.Close(); err != nil {
		t.Fatal(err)
	}
	archive, err := os.Create(filepath.Join(root, "rootfs.tar"))
	if err != nil {
		t.Fatal(err)
	}
	defer archive.Close()
	input, err := os.Open(binary)
	if err != nil {
		t.Fatal(err)
	}
	defer input.Close()
	info, err := input.Stat()
	if err != nil {
		t.Fatal(err)
	}
	tw := tar.NewWriter(archive)
	if err = tw.WriteHeader(&tar.Header{Name: "backend", Mode: 0755, Size: info.Size()}); err != nil {
		t.Fatal(err)
	}
	if _, err = io.Copy(tw, input); err != nil {
		t.Fatal(err)
	}
	if len(files) > 16 {
		t.Fatal("too many fixture files")
	}
	var names []string
	for name, data := range files {
		if name == "" || name == "backend" || name == "." || name == ".." || strings.ContainsAny(name, "/\\\x00\r\n") || len(name) > 128 || len(data) > 1<<20 {
			t.Fatal("invalid explicit fixture file")
		}
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		data := files[name]
		if err = tw.WriteHeader(&tar.Header{Name: name, Typeflag: tar.TypeReg, Mode: 0444, Size: int64(len(data))}); err != nil {
			t.Fatal(err)
		}
		if _, err = tw.Write(data); err != nil {
			t.Fatal(err)
		}
	}
	if err = tw.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err = archive.Seek(0, io.SeekStart); err != nil {
		t.Fatal(err)
	}
	if beforeImport != nil {
		beforeImport()
	}
	configured := append([]string{`CMD ["/backend"]`}, changes...)
	configured = append(configured, "LABEL org.mydc.test.owner="+tag)
	stream, err := c.API.ImageImport(ctx, client.ImageImportSource{Source: archive, SourceName: "-"}, f.ImageRef, client.ImageImportOptions{Changes: configured})
	if err != nil {
		t.Fatal(err)
	}
	d := json.NewDecoder(stream)
	for {
		var msg struct{ Error string }
		err = d.Decode(&msg)
		if err == io.EOF {
			break
		}
		if err != nil || msg.Error != "" {
			stream.Close()
			t.Fatal("image import", msg.Error, err)
		}
	}
	if err = stream.Close(); err != nil {
		t.Fatal(err)
	}
	image, err := c.API.ImageInspect(ctx, f.ImageRef)
	if err != nil {
		t.Fatal(err)
	}
	f.Image = image.ID
	t.Logf("nativeOwner=%s image=%s imageRef=%s", owner, f.Image, f.ImageRef)
	return f
}
