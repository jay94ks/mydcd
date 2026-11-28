// SPDX-License-Identifier: Apache-2.0

package deployment

import (
	"encoding/json"
	"slices"
	"strings"

	"github.com/jay94ks/seafield/internal/access"
)

// A deploy resolves each tag its tasks name once, before any of those tasks is
// prepared, and every container the deploy creates uses that digest
// (devel/design: tags are never pinned; only instantiated containers keep a
// digest). The resolution lives in the Execution and goes away with it.

// ImageResolution is one tag reference's resolution for one deploy: Digest
// (repo@sha256:…) when the registry answered, otherwise Code.
type ImageResolution struct {
	Ref    string
	Digest string `json:",omitempty"`
	Code   string `json:",omitempty"`
}

// ImageResolutionCodes are the failure codes a resolution may carry
// (ResolutionCode folds image resolve's codes into these).
var ImageResolutionCodes = []string{"UNREACHABLE", "NOT_FOUND", "UNTRUSTED", "DENIED", "SOURCE_REVOKED", "INVALID_IMAGE"}

// ResolutionCode folds an image resolve code (control.ImageResolveTarget or
// the registry client) into ImageResolutionCodes; "" for one to retry later
// rather than record (the resolver was cancelled).
func ResolutionCode(code string) string {
	switch code {
	case "CANCELLED", "CLOSED":
		return ""
	case "UNAVAILABLE", "SOURCE_NOT_READY", "TIMEOUT", "RATE_LIMITED", "PLAIN_HTTP", "INVALID_CA":
		return "UNREACHABLE"
	case "NOT_FOUND", "UNTRUSTED", "SOURCE_REVOKED":
		return code
	case "DENIED", "UNAUTHORIZED", "AUTH_SCOPE", "INVALID_CREDENTIAL", "AUTHORITY_MISMATCH":
		return "DENIED"
	}
	return "INVALID_IMAGE"
}

// LocalCopyAllowed reports whether a server may create the container from
// its own last copy of the tag: the registry could not be reached, or it
// answered that the tag or image is gone (removed by mistake upstream). A
// policy refusal (trust, permission, revoked source) never falls back.
func LocalCopyAllowed(code string) bool { return code == "UNREACHABLE" || code == "NOT_FOUND" }

// TagReference returns ref normalized when it names a tag (no digest), so a
// deploy must resolve it.
func TagReference(ref string) (string, bool) {
	if strings.Contains(ref, "@") {
		return "", false
	}
	// The same normalization app.yaml gets (compose parse).
	normalized, err := access.NormalizeImage(ref)
	if err != nil || strings.Contains(normalized, "@") {
		return "", false
	}
	return normalized, true
}

func (r ImageResolution) valid() bool {
	if normalized, ok := TagReference(r.Ref); !ok || normalized != r.Ref {
		return false
	}
	if (r.Digest == "") == (r.Code == "") {
		return false
	}
	if r.Code != "" {
		return slices.Contains(ImageResolutionCodes, r.Code)
	}
	repo, digest, ok := strings.Cut(r.Digest, "@sha256:")
	return ok && len(digest) == 64 && strings.Trim(digest, "0123456789abcdef") == "" && repo == repository(r.Ref)
}

// stepImage is the tag a task step names, normalized; false for other steps
// and for digest references.
func stepImage(s Step) (string, bool) {
	if s.Kind != "task" {
		return "", false
	}
	// A plan's task Goal is the ComposeService itself; GoalCommand wraps it
	// only when the command is sent.
	var service struct{ Image string }
	if json.Unmarshal(s.Goal, &service) != nil {
		return "", false
	}
	return TagReference(service.Image)
}

// TagImages lists the tags this deploy's tasks name, sorted, without
// duplicates.
func (e Execution) TagImages() []string {
	var out []string
	for _, s := range e.d.Plan.Steps {
		if ref, ok := stepImage(s); ok && !slices.Contains(out, ref) {
			out = append(out, ref)
		}
	}
	slices.Sort(out)
	return out
}

// ImagesPending reports whether the deploy still has to resolve its tags.
func (e Execution) ImagesPending() bool {
	return e.d.Images == nil && len(e.TagImages()) > 0
}

// Image returns the deploy's resolution of the normalized tag ref.
func (e Execution) Image(ref string) (ImageResolution, bool) {
	i := slices.IndexFunc(e.d.Images, func(r ImageResolution) bool { return r.Ref == ref })
	if i < 0 {
		return ImageResolution{}, false
	}
	return e.d.Images[i], true
}

// ResolveImages records the deploy's tag resolutions, once: images must name
// exactly TagImages, in order.
func (e Execution) ResolveImages(expected uint64, images []ImageResolution) (Execution, error) {
	if e.d.Revision != expected || e.d.Stopping || !e.ImagesPending() || !validImages(e.TagImages(), images) {
		return e, ErrInputs
	}
	next, err := e.clone()
	if err != nil {
		return e, err
	}
	next.d.Images = slices.Clone(images)
	return next, nil
}

func validImages(tags []string, images []ImageResolution) bool {
	if len(images) != len(tags) {
		return false
	}
	for i, r := range images {
		if r.Ref != tags[i] || !r.valid() {
			return false
		}
	}
	return true
}

// imagesReady holds back a task step until the deploy has resolved its tag.
func (e Execution) imagesReady(i int) bool {
	if _, ok := stepImage(e.d.Plan.Steps[i]); !ok {
		return true
	}
	return e.d.Images != nil
}

// repository is a normalized tag or digest reference without its tag or
// digest.
func repository(ref string) string {
	if repo, _, ok := strings.Cut(ref, "@"); ok {
		return repo
	}
	slash := strings.LastIndex(ref, "/")
	name, _, _ := strings.Cut(ref[slash+1:], ":")
	return ref[:slash+1] + name
}

// TagAllows reports whether a container for a Task naming tag may be made
// from digest (repo@sha256:…): the deploy resolved the tag to it, or could
// not and lets each server use its own copy of the same repository.
func (e Execution) TagAllows(tag, digest string) bool {
	ref, ok := TagReference(tag)
	if !ok {
		return false
	}
	r, ok := e.Image(ref)
	switch {
	case !ok:
		return false
	case r.Digest != "":
		return r.Digest == digest
	}
	return LocalCopyAllowed(r.Code) && strings.Contains(digest, "@sha256:") && repository(digest) == repository(ref)
}

// TaskImage is the image a Task's container is made from when its service
// names a tag: Digest (repo@sha256:…) and, for this server's own copy,
// Source (workload.ImageSources). Zero for a digest reference.
type TaskImage struct{ Digest, Source string }

// TaskImageFor chooses the image for a Task naming ref on this server:
// the deploy's digest, or local (this server's last digest for the tag,
// "" when none) when the deploy could not resolve it and may fall back. A
// non-empty failure is the Task's failure code.
func (e Execution) TaskImageFor(ref, local string) (image TaskImage, tag, failure string) {
	tag, ok := TagReference(ref)
	if !ok {
		return TaskImage{}, "", ""
	}
	r, ok := e.Image(tag)
	switch {
	case !ok:
		return TaskImage{}, tag, FailureImageInvalid
	case r.Digest != "":
		return TaskImage{Digest: r.Digest}, tag, ""
	case !LocalCopyAllowed(r.Code) || local == "" || !e.TagAllows(tag, local):
		return TaskImage{}, tag, ImageFailure(r.Code)
	case r.Code == "NOT_FOUND":
		return TaskImage{Digest: local, Source: "registry-missing"}, tag, ""
	}
	return TaskImage{Digest: local, Source: "registry-unreachable"}, tag, ""
}
