// SPDX-License-Identifier: Apache-2.0

package control

import (
	"github.com/jay94ks/mydcd/internal/access"
	"github.com/jay94ks/mydcd/internal/cluster/state"
	"github.com/jay94ks/mydcd/internal/registryclient"
)

// The selected child is not an independent image grant. Its entire path is
// checked by the source owner against the immutable accepted FROM root.
type ImageBuildBaseContentRead struct {
	Read  ImageBuildBaseRead
	Query registryclient.GraphContentQuery
}

func (p Policy) CurrentImageBuildBaseContent(s state.State, q ImageBuildBaseContentRead, at int64) (ImageBuildBaseRead, error) {
	if !q.Query.Valid() || q.Query.Root != q.Read.Target.Normalized {
		return ImageBuildBaseRead{}, access.ErrDenied
	}
	return p.CurrentImageBuildBaseMaterial(s, q.Read, at)
}
