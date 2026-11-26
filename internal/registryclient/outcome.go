// SPDX-License-Identifier: Apache-2.0

package registryclient

// PullOutcome describes actual remote image work, never a login/HEAD probe or
// an already cached image. A successful load includes its final Docker inspect.
type PullOutcome struct{ Stage, Code string }

func (o PullOutcome) Valid() bool {
	return (o.Stage == "resolve" && o.Code != "OK" || o.Stage == "load") && ValidResultCode(o.Code)
}

// A foreign error body or an arbitrary Error.Code must not become observation
// text. Keep the finite public vocabulary at the registry I/O boundary.
func ValidResultCode(code string) bool {
	switch code {
	case "OK", "CANCELLED", "TIMEOUT", "UNAUTHORIZED", "DENIED", "NOT_FOUND", "UNSUPPORTED", "UNAVAILABLE", "CLOSED", "INVALID_IMAGE", "IMAGE_BUDGET", "METADATA_BUDGET", "INVALID_CA", "INVALID_CREDENTIAL", "INVALID_SOURCE", "AUTHORITY_MISMATCH", "AUTH_SCOPE", "IMAGE_LOAD_FAILED", "PRIVATE_INPUT", "CATALOGUE_CHANGED", "PLAIN_HTTP", "PLATFORM_MISMATCH":
		return true
	}
	return false
}

func ResultCode(err error) string {
	if err == nil {
		return "OK"
	}
	return Sanitize(err).Error()
}
