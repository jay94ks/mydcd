// SPDX-License-Identifier: Apache-2.0

package imagebuild

import "github.com/jay94ks/seafield/internal/registryclient"

// NativePublication is the original output and ordered tag attempts in the
// existing node journal. Started does not imply that the root PUT was sent.
type NativePublication struct {
	Output registryclient.ImageMetadata
	Tags   []NativePublishTag
}
type NativePublishTag struct {
	Target        string
	Started, Sent bool
	Code          string
	At            uint64
}

func (p NativePublication) validate(spec JobSpec) error {
	if !p.Output.Valid() || p.Output.Repository != spec.Context.Repository || p.Output.Reference != p.Output.Digest || p.Output.ImageBytes <= 0 {
		return ErrStorage
	}
	tags, err := spec.OutputTags()
	if err != nil || len(tags) != len(p.Tags) {
		return ErrStorage
	}
	previousOK := true
	for i, tag := range p.Tags {
		if tag.Target != tags[i] || tag.Sent && !tag.Started || !previousOK && (tag.Started || tag.Code != "") || (tag.Code == "") != (tag.At == 0) {
			return ErrStorage
		}
		switch tag.Code {
		case "":
		case "OK", "UNKNOWN":
			if !tag.Sent {
				return ErrStorage
			}
		default:
			if !registryclient.ValidResultCode(tag.Code) || tag.Sent && tag.Code != "DENIED" && tag.Code != "UNAUTHORIZED" && tag.Code != "UNSUPPORTED" {
				return ErrStorage
			}
		}
		previousOK = tag.Code == "OK"
	}
	return nil
}

func newPublication(spec JobSpec, output registryclient.ImageMetadata) (NativePublication, error) {
	targets, err := spec.OutputTags()
	if err != nil {
		return NativePublication{}, err
	}
	p := NativePublication{Output: output}
	for _, target := range targets {
		p.Tags = append(p.Tags, NativePublishTag{Target: target})
	}
	if err := p.validate(spec); err != nil {
		return NativePublication{}, err
	}
	return p, nil
}

// result cannot turn a sent unknown root into failure/cancellation, or an
// unattempted suffix into success. A confirmed prefix plus a known failure is
// a failed build publication; existing content/tags are not rolled back.
func (p NativePublication) result(spec JobSpec) (JobResult, bool) {
	failure := ""
	for _, tag := range p.Tags {
		if tag.Code == "UNKNOWN" || tag.Sent && tag.Code == "" {
			return JobResult{}, false
		}
		if tag.Code == "" {
			if failure == "" {
				return JobResult{}, false
			}
			continue
		}
		if tag.Code == "OK" {
			continue
		}
		switch tag.Code {
		case "CANCELLED":
			// SDK cancellation is not proof of the user's shared Run.Cancel.
			// The reporting owner checks that separately when signing closure.
			failure = "BUILD_FAILED"
		case "TIMEOUT":
			failure = "TIMEOUT"
		case "DENIED", "UNAUTHORIZED":
			failure = "PERMISSION_REVOKED"
		case "UNAVAILABLE", "CLOSED":
			failure = "STORAGE_UNAVAILABLE"
		default:
			failure = "BUILD_FAILED"
		}
	}
	if failure != "" {
		return JobResult{Code: failure}, true
	}
	return JobResult{Code: "OK", Image: spec.OutputRepository() + "@" + p.Output.Digest, Bytes: p.Output.ImageBytes}, true
}
