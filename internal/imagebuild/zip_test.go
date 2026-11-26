// SPDX-License-Identifier: Apache-2.0

package imagebuild

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/binary"
	"io/fs"
	"strings"
	"testing"
)

type zipInput struct {
	name, body string
	mode       fs.FileMode
	extra      []byte
}

func makeZIP(t *testing.T, entries ...zipInput) []byte {
	t.Helper()
	var buffer bytes.Buffer
	w := zip.NewWriter(&buffer)
	for _, entry := range entries {
		mode := entry.mode
		if mode == 0 {
			mode = 0600
		}
		header := &zip.FileHeader{Name: entry.name, Method: zip.Store, Extra: entry.extra}
		header.SetMode(mode)
		file, err := w.CreateHeader(header)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := file.Write([]byte(entry.body)); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return buffer.Bytes()
}

func TestZIPTreeOrderAndLimits(t *testing.T) {
	entries := []zipInput{{name: "src/run", body: "#!/bin/sh\n", mode: 0700}, {name: "Dockerfile", body: "FROM scratch\n"}, {name: "empty/", mode: fs.ModeDir | 0700}}
	raw := makeZIP(t, entries...)
	tree, err := InspectZIP(context.Background(), bytes.NewReader(raw), int64(len(raw)), "Dockerfile", 100)
	if err != nil || len(tree.Entries) != 3 || tree.Entries[0].Path != "Dockerfile" || !tree.Entries[2].Executable {
		t.Fatal(tree, err)
	}
	other := makeZIP(t, entries[2], entries[1], entries[0])
	reordered, err := InspectZIP(context.Background(), bytes.NewReader(other), int64(len(other)), "Dockerfile", 100)
	if err != nil || tree.Digest() != reordered.Digest() {
		t.Fatal("ZIP order affects immutable tree", err)
	}
	if _, err := InspectZIP(context.Background(), bytes.NewReader(raw), int64(len(raw)), "Dockerfile", tree.Bytes-1); err == nil {
		t.Fatal("expanded limit ignored")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := InspectZIP(ctx, bytes.NewReader(raw), int64(len(raw)), "Dockerfile", 100); err == nil {
		t.Fatal("cancel ignored")
	}
}

func TestZIPRejectsUnsafeEntries(t *testing.T) {
	cases := map[string][]zipInput{
		"escape":           {{name: "../Dockerfile", body: "FROM scratch"}},
		"absolute":         {{name: "/Dockerfile", body: "FROM scratch"}},
		"backslash":        {{name: "x\\Dockerfile"}},
		"duplicate":        {{name: "Dockerfile"}, {name: "Dockerfile"}},
		"prefix":           {{name: "a/b/c"}, {name: "a/b"}},
		"link":             {{name: "Dockerfile", body: "target", mode: fs.ModeSymlink | 0600}},
		"device":           {{name: "Dockerfile", mode: fs.ModeDevice | 0600}},
		"pipe":             {{name: "Dockerfile", mode: fs.ModeNamedPipe | 0600}},
		"extra-link":       {{name: "Dockerfile", extra: []byte{0x6e, 0x75, 0, 0}}},
		"missing":          {{name: "source.go", body: "package main"}},
		"large-dockerfile": {{name: "Dockerfile", body: strings.Repeat("#", MaxDockerfileBytes+1)}},
	}
	for name, entries := range cases {
		t.Run(name, func(t *testing.T) {
			if name != "missing" {
				hasDockerfile := false
				for _, entry := range entries {
					if entry.name == "Dockerfile" {
						hasDockerfile = true
					}
				}
				if !hasDockerfile {
					entries = append(entries, zipInput{name: "Dockerfile", body: "FROM scratch\n"})
				}
			}
			raw := makeZIP(t, entries...)
			if _, err := InspectZIP(context.Background(), bytes.NewReader(raw), int64(len(raw)), "Dockerfile", MaxExpandedBytes); err == nil {
				t.Fatal("unsafe ZIP accepted")
			}
		})
	}
}

func TestZIPRejectsChangedCRC(t *testing.T) {
	raw := makeZIP(t, zipInput{name: "Dockerfile", body: "FROM scratch\n"})
	index := bytes.Index(raw, []byte("FROM scratch"))
	if index < 0 {
		t.Fatal("fixture")
	}
	raw[index] = 'X'
	if _, err := InspectZIP(context.Background(), bytes.NewReader(raw), int64(len(raw)), "Dockerfile", 100); err == nil {
		t.Fatal("CRC mismatch accepted")
	}
}

func TestZIPDirectoryBudgetsBeforeDecoderAllocations(t *testing.T) {
	original := makeZIP(t, zipInput{name: "Dockerfile", body: "FROM scratch\n"})
	for _, count := range []uint16{2, MaxTreeEntries + 1, 65535} {
		raw := append([]byte(nil), original...)
		end := bytes.LastIndex(raw, []byte{'P', 'K', 5, 6})
		if end < 0 {
			t.Fatal("fixture")
		}
		binary.LittleEndian.PutUint16(raw[end+8:], count)
		binary.LittleEndian.PutUint16(raw[end+10:], count)
		if _, err := InspectZIP(context.Background(), bytes.NewReader(raw), int64(len(raw)), "Dockerfile", 100); err == nil {
			t.Fatal("unbounded or inconsistent directory admitted", count)
		}
	}
}
