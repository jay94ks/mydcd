// SPDX-License-Identifier: Apache-2.0

package imagebuild

import (
	"errors"
	"strings"
	"testing"
)

func TestDockerfileUsesUpstreamStageAndImageSemantics(t *testing.T) {
	body := "ARG BASE=alpine:3.22\nFROM --platform=$TARGETPLATFORM ${BASE} AS alpine\nRUN --mount=from=busybox:1.37,source=/bin,target=/tools echo ok\nFROM scratch\nCOPY --from=alpine /bin/sh /bin/sh\nCOPY --from=ghcr.io/acme/tool:latest /tool /tool\n"
	plan, err := AnalyzeDockerfile([]byte(body), DockerfileOptions{Platform: "linux/amd64", BuildPlatform: "linux/amd64", Arguments: map[string]string{"BASE": "alpine:3.23"}})
	if err != nil || len(plan.Sources) != 3 || plan.Sources[0].Reference != "docker.io/library/alpine:3.23" || plan.Sources[1].Kind != "mount" || plan.Sources[2].Kind != "copy" {
		t.Fatal(plan, err)
	}
	var seen []Source
	frozen, err := FreezeSources(plan, func(source Source) (string, error) {
		seen = append(seen, source)
		name := strings.Split(source.Reference, ":")[0]
		return name + "@sha256:" + strings.Repeat("a", 64), nil
	})
	if err != nil || len(frozen) != 3 || len(seen) != 3 {
		t.Fatal(frozen, err)
	}
	if _, err := FreezeSources(plan, func(Source) (string, error) { return "docker.io/library/other@sha256:" + strings.Repeat("b", 64), nil }); err == nil {
		t.Fatal("resolver substituted repository")
	}
}

func TestDockerfileSourceQueryRejectsNoncanonicalAndOutOfRangeCoordinates(t *testing.T) {
	source := Source{Reference: "docker.io/library/alpine:latest", Platform: "linux/amd64", Stage: 0, Kind: "from", Line: 1}
	if !source.Valid() {
		t.Fatal("valid analyzed source rejected")
	}
	for _, edit := range []func(*Source){
		func(s *Source) { s.Reference = "alpine:latest" }, func(s *Source) { s.Reference = "https://example/image" },
		func(s *Source) { s.Stage = -1 }, func(s *Source) { s.Stage = MaxTreeEntries }, func(s *Source) { s.Line = -1 },
		func(s *Source) { s.Kind = "exec" }, func(s *Source) { s.Platform = "../host" },
	} {
		bad := source
		edit(&bad)
		if bad.Valid() {
			t.Fatal("invalid source query accepted", bad)
		}
	}
}

func TestDockerfileRejectsUntrustedAndCyclesWithoutFallback(t *testing.T) {
	options := DockerfileOptions{Platform: "linux/amd64", BuildPlatform: "linux/amd64"}
	for _, body := range []string{
		"# syntax=docker/dockerfile:1\nFROM scratch\n",
		"FROM $MISSING\n", "FROM scratch AS a\nCOPY --from=a /x /x\n",
		"FROM scratch AS a\nCOPY --from=b /x /x\nFROM scratch AS b\nCOPY --from=a /x /x\n",
		"FROM scratch\nCOPY --from=99 /x /x\n",
	} {
		if _, err := AnalyzeDockerfile([]byte(body), options); err == nil {
			t.Fatalf("invalid Dockerfile accepted: %q", body)
		}
	}
	plan, err := AnalyzeDockerfile([]byte("FROM alpine AS alpine\nFROM alpine\n"), options)
	if err != nil || len(plan.Sources) != 1 {
		t.Fatal("image/stage alias distinction", plan, err)
	}
	for _, failure := range []error{ErrUntrustedBase, errors.New("credential MUST-NOT-LEAK")} {
		calls := 0
		result, err := FreezeSources(plan, func(Source) (string, error) { calls++; return "", failure })
		if err == nil || len(result) != 0 || calls != 1 || strings.Contains(err.Error(), "MUST-NOT-LEAK") {
			t.Fatal("failed lookup escaped boundary", result, err)
		}
	}
}

func TestDockerfileAutomaticARGOverridesMatchBuilder(t *testing.T) {
	plan, err := AnalyzeDockerfile([]byte("FROM --platform=$TARGETPLATFORM alpine\n"), DockerfileOptions{Platform: "linux/amd64", BuildPlatform: "linux/amd64", Arguments: map[string]string{"TARGETPLATFORM": "linux/arm64"}})
	if err != nil || len(plan.Sources) != 1 || plan.Sources[0].Platform != "linux/arm64" {
		t.Fatal(plan, err)
	}
	if _, err := AnalyzeDockerfile([]byte("FROM scratch\n"), DockerfileOptions{Platform: "linux/amd64", BuildPlatform: "linux/amd64", Arguments: map[string]string{"BUILDKIT_SYNTAX": "unapproved/frontend:latest"}}); err == nil {
		t.Fatal("build argument overrides fixed frontend")
	}
}
