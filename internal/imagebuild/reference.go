// SPDX-License-Identifier: Apache-2.0

package imagebuild

import (
	"errors"

	"github.com/distribution/reference"
)

// parseCanonical parses a fully qualified, digest-pinned reference
// ("registry/repo@sha256:..."). github.com/distribution/reference has no
// ParseCanonical, so this keeps the intended meaning: the string must already
// be in canonical (fully qualified) form, carry a digest and no tag.
func parseCanonical(s string) (reference.Canonical, error) {
	named, err := reference.ParseNamed(s)
	if err != nil {
		return nil, err
	}
	if _, tagged := named.(reference.Tagged); tagged {
		return nil, errors.New("reference must not carry a tag")
	}
	canonical, ok := named.(reference.Canonical)
	if !ok {
		return nil, errors.New("reference must be pinned by digest")
	}
	return canonical, nil
}
