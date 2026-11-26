// SPDX-License-Identifier: Apache-2.0

package lifecycle

import (
	"bytes"
	_ "embed"
)

// The materializer emits this actual SDK file, not a handwritten second SDK.
//
//go:embed contract.go
var contractSource []byte

func CompilationSources() map[string][]byte {
	return map[string][]byte{"contract.go": bytes.Clone(contractSource)}
}
