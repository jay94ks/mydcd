// SPDX-License-Identifier: Apache-2.0

package deployment

import (
	"encoding/json"
	"slices"
	"strings"
	"testing"
)

func taskStep(t *testing.T, key, image string) Step {
	t.Helper()
	goal, _ := json.Marshal(map[string]string{"Image": image})
	return Step{Key: key, Kind: "task", Goal: goal}
}

func imageExecution(t *testing.T, images ...string) Execution {
	t.Helper()
	e := Execution{executionRecord{Schema: 1, Revision: 1, Operation: "op", Submitter: "user/a", Epoch: 1}}
	for i, image := range images {
		key := "task/" + string(rune('a'+i))
		e.d.Plan.Steps = append(e.d.Plan.Steps, taskStep(t, key, image))
		e.d.Stages = append(e.d.Stages, StageRecord{Key: key})
	}
	e.d.Plan.Steps = append(e.d.Plan.Steps, Step{Key: "bridge/x", Kind: "bridge"})
	e.d.Stages = append(e.d.Stages, StageRecord{Key: "bridge/x"})
	return e
}

var (
	webDigest = "ghcr.io/team/web@sha256:" + strings.Repeat("a", 64)
	webOther  = "ghcr.io/team/web@sha256:" + strings.Repeat("b", 64)
)

// A deploy resolves each tag once; its tasks wait for that, other steps do
// not, and every task naming the tag then uses the one digest.
func TestDeployResolvesEachTagOnce(t *testing.T) {
	e := imageExecution(t, "ghcr.io/team/web:1", "alpine", "ghcr.io/team/web:1", "ghcr.io/team/db@sha256:"+strings.Repeat("c", 64))
	tags := e.TagImages()
	if len(tags) != 2 || tags[0] != "docker.io/library/alpine:latest" || tags[1] != "ghcr.io/team/web:1" {
		t.Fatal("tags", tags)
	}
	if !e.ImagesPending() || e.imagesReady(0) || !e.imagesReady(3) || !e.imagesReady(4) {
		t.Fatal("tasks naming a tag must wait; digest tasks and other steps must not")
	}
	if len(e.WaitingOn("task/a", 0)) == 0 {
		t.Fatal("waiting reason missing")
	}
	images := []ImageResolution{{Ref: "docker.io/library/alpine:latest", Code: "UNREACHABLE"}, {Ref: "ghcr.io/team/web:1", Digest: webDigest}}
	for _, bad := range [][]ImageResolution{
		images[:1],
		{images[1], images[0]},
		{images[0], {Ref: "ghcr.io/team/web:1", Digest: "ghcr.io/team/other@sha256:" + strings.Repeat("a", 64)}},
		{images[0], {Ref: "ghcr.io/team/web:1", Digest: webDigest, Code: "NOT_FOUND"}},
		{{Ref: "docker.io/library/alpine:latest", Code: "ELSEWHERE"}, images[1]},
	} {
		if _, err := e.ResolveImages(1, bad); err == nil {
			t.Fatal("bad resolutions accepted", bad)
		}
	}
	if _, err := e.ResolveImages(2, images); err == nil {
		t.Fatal("stale revision accepted")
	}
	next, err := e.ResolveImages(1, images)
	if err != nil || next.Revision() != 2 || next.ImagesPending() || !next.imagesReady(0) {
		t.Fatal("resolve", err)
	}
	if _, err := next.ResolveImages(2, images); err == nil {
		t.Fatal("resolved twice")
	}
	if img, tag, failure := next.TaskImageFor("ghcr.io/team/web:1", webOther); failure != "" || tag != "ghcr.io/team/web:1" || img != (TaskImage{Digest: webDigest}) {
		t.Fatal("resolved tag must use the deploy's digest, not the local copy", img, failure)
	}
	if !next.TagAllows("ghcr.io/team/web:1", webDigest) || next.TagAllows("ghcr.io/team/web:1", webOther) {
		t.Fatal("TagAllows on a resolved tag")
	}
}

// Unreachable or missing registries fall back to this server's own copy;
// policy refusals and a missing copy end the task.
func TestTaskImageLocalCopy(t *testing.T) {
	alpine := "docker.io/library/alpine@sha256:" + strings.Repeat("d", 64)
	for _, c := range []struct {
		code, local string
		want        TaskImage
		failure     string
	}{
		{"UNREACHABLE", alpine, TaskImage{Digest: alpine, Source: "registry-unreachable"}, ""},
		{"NOT_FOUND", alpine, TaskImage{Digest: alpine, Source: "registry-missing"}, ""},
		{"UNREACHABLE", "", TaskImage{}, FailureImageUnreachable},
		{"NOT_FOUND", webDigest, TaskImage{}, FailureImageNotFound}, // another repository
		{"UNTRUSTED", alpine, TaskImage{}, FailureImageUntrusted},
		{"DENIED", alpine, TaskImage{}, FailureImageDenied},
		{"SOURCE_REVOKED", alpine, TaskImage{}, FailureImageRevoked},
	} {
		e := imageExecution(t, "alpine")
		e, err := e.ResolveImages(1, []ImageResolution{{Ref: "docker.io/library/alpine:latest", Code: c.code}})
		if err != nil {
			t.Fatal(err)
		}
		img, _, failure := e.TaskImageFor("alpine", c.local)
		if img != c.want || failure != c.failure || failureText(failure) == "" && failure != "" {
			t.Fatal(c.code, c.local, img, failure)
		}
	}
	if img, tag, failure := imageExecution(t).TaskImageFor(webDigest, ""); img != (TaskImage{}) || tag != "" || failure != "" {
		t.Fatal("digest reference", img, tag, failure)
	}
}

func TestResolutionCode(t *testing.T) {
	for in, want := range map[string]string{"UNAVAILABLE": "UNREACHABLE", "SOURCE_NOT_READY": "UNREACHABLE", "TIMEOUT": "UNREACHABLE", "NOT_FOUND": "NOT_FOUND", "UNAUTHORIZED": "DENIED", "UNTRUSTED": "UNTRUSTED", "PLATFORM_MISMATCH": "INVALID_IMAGE", "CANCELLED": ""} {
		if got := ResolutionCode(in); got != want {
			t.Errorf("ResolutionCode(%s) = %q", in, got)
		}
	}
}

// A real compiled plan: the task Goal is the ComposeService, and a tag in
// app.yaml makes the deploy wait for one resolution.
func TestCompiledTagWaitsForResolution(t *testing.T) {
	f := makeFixture(t)
	ctx := contextFor(t, f)
	raw := strings.ReplaceAll(composeFixture, "DIGEST", strings.Repeat("a", 64))
	raw = strings.Replace(raw, "docker.io/library/php@sha256:"+strings.Repeat("a", 64), "php:8.3-fpm", 1)
	c, err := ParseCompose([]byte(raw))
	if err != nil {
		t.Fatal(err)
	}
	b, err := Compile(c, f.c, ctx)
	if err != nil {
		t.Fatal(err)
	}
	e, err := NewExecution(b, f.c, ctx, "operation", "submitter", 1)
	if err != nil {
		t.Fatal(err)
	}
	if got := e.TagImages(); !slices.Equal(got, []string{"docker.io/library/php:8.3-fpm"}) {
		t.Fatalf("tags %v", got)
	}
	web := e.index(ResourceKey("task", "tenant", "php-mysql", "web"))
	db := e.index(ResourceKey("task", "tenant", "php-mysql", "db"))
	if web < 0 || db < 0 || !e.ImagesPending() || e.imagesReady(web) || !e.imagesReady(db) {
		t.Fatal("tag task did not wait for resolution")
	}
	digest := "docker.io/library/php@sha256:" + strings.Repeat("c", 64)
	e, err = e.ResolveImages(e.Revision(), []ImageResolution{{Ref: "docker.io/library/php:8.3-fpm", Digest: digest}})
	if err != nil {
		t.Fatal(err)
	}
	if !e.imagesReady(web) || !e.TagAllows("php:8.3-fpm", digest) {
		t.Fatal("resolved tag not usable")
	}
	if image, _, failure := e.TaskImageFor("docker.io/library/php:8.3-fpm", ""); failure != "" || image.Digest != digest {
		t.Fatalf("task image %+v %s", image, failure)
	}
}
