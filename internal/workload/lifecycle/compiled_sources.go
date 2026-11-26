// SPDX-License-Identifier: Apache-2.0

package lifecycle

import (
	"bytes"
	"embed"
	"io/fs"
	"path"

	"github.com/jay94ks/mydcd/internal/schema"
	contract "github.com/jay94ks/mydcd/lifecycle/v1"
)

// Only these dependency-free actual product files are emitted into compiled
// helpers. Yaegi/DB/daemon code and credentials never enter this source view.
//
//go:embed contract.go opaque_probe.go probe_rpc.go compiled_runner.go
var compiledCoreSources embed.FS

func trustedCompileSources() map[string][]byte {
	out := map[string][]byte{}
	for name, data := range contract.CompilationSources() {
		out[path.Join(resolverGoPath, "src", checkerSDK, name)] = data
	}
	for name, data := range schema.CompilationSources() {
		out[path.Join(resolverGoPath, "src/github.com/jay94ks/mydcd/internal/schema", name)] = data
	}
	files, _ := fs.ReadDir(compiledCoreSources, ".")
	for _, file := range files {
		data, _ := compiledCoreSources.ReadFile(file.Name())
		out[path.Join(resolverGoPath, "src/github.com/jay94ks/mydcd/internal/workload/lifecycle", file.Name())] = bytes.Clone(data)
	}
	return out
}
