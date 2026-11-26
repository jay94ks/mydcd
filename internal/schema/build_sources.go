// SPDX-License-Identifier: Apache-2.0

package schema

import (
	"bytes"
	_ "embed"
)

//go:embed json.go
var canonicalSource []byte

//go:embed input.go
var inputSource []byte

func CompilationSources() map[string][]byte {
	return map[string][]byte{"json.go": bytes.Clone(canonicalSource), "input.go": bytes.Clone(inputSource)}
}
