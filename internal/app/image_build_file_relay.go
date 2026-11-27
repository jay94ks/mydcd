// SPDX-License-Identifier: Apache-2.0

package app

import (
	"errors"

	"github.com/jay94ks/seafield/internal/access"
	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/imagebuild"
	"github.com/jay94ks/seafield/internal/schema"
	"github.com/jay94ks/seafield/internal/sfcp"
)

// File reads preserve their bounded user-facing conflict/error category through
// the existing authenticated owner relay. Native paths and error text stay local.
type imageBuildFileOwnerReply struct {
	Code    string
	Content *control.ImageBuildContentPage `json:",omitempty"`
	Draft   *imagebuild.DraftResponse      `json:",omitempty"`
}

func imageBuildFileReadCode(err error) string {
	if err == nil {
		return "ok"
	}
	if errors.Is(err, access.ErrDenied) {
		return "denied"
	}
	if errors.Is(err, access.ErrConflict) || errors.Is(err, imagebuild.ErrConflict) {
		return "conflict"
	}
	if errors.Is(err, access.ErrInvalid) || errors.Is(err, imagebuild.ErrInvalid) {
		return "invalid"
	}
	return "unavailable"
}
func imageBuildFileReadError(code string) error {
	switch code {
	case "ok":
		return nil
	case "conflict":
		return imagebuild.ErrConflict
	case "invalid":
		return imagebuild.ErrInvalid
	case "denied":
		return access.ErrDenied
	default:
		return sfcp.ErrAdmission
	}
}

func decodeImageBuildFileContent(raw []byte, read control.ImageBuildContentRead) (control.ImageBuildContentPage, error) {
	if read.Query.Part != "file" || !read.Query.Valid() {
		return control.ImageBuildContentPage{}, sfcp.ErrAdmission
	}
	result, err := schema.Decode[imageBuildFileOwnerReply](raw)
	if err != nil || result.Draft != nil {
		return control.ImageBuildContentPage{}, sfcp.ErrAdmission
	}
	if err = imageBuildFileReadError(result.Code); err != nil {
		if result.Content != nil {
			return control.ImageBuildContentPage{}, sfcp.ErrAdmission
		}
		return control.ImageBuildContentPage{}, err
	}
	if result.Content == nil || !result.Content.Valid(read) {
		return control.ImageBuildContentPage{}, sfcp.ErrAdmission
	}
	return *result.Content, nil
}
func decodeImageBuildFileDraft(raw []byte, q imagebuild.DraftRequest, scope imagebuild.DraftScope) (imagebuild.DraftResponse, error) {
	if q.Kind != "file" || !q.Valid() || q.Scope == nil || *q.Scope != scope {
		return imagebuild.DraftResponse{}, sfcp.ErrAdmission
	}
	result, err := schema.Decode[imageBuildFileOwnerReply](raw)
	if err != nil || result.Content != nil {
		return imagebuild.DraftResponse{}, sfcp.ErrAdmission
	}
	if err = imageBuildFileReadError(result.Code); err != nil {
		if result.Draft != nil {
			return imagebuild.DraftResponse{}, sfcp.ErrAdmission
		}
		return imagebuild.DraftResponse{}, err
	}
	if result.Draft == nil || !result.Draft.Valid(q) || result.Draft.Scope != scope {
		return imagebuild.DraftResponse{}, sfcp.ErrAdmission
	}
	return *result.Draft, nil
}
