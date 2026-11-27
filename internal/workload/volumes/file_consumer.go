// SPDX-License-Identifier: Apache-2.0

package volumes

import "github.com/jay94ks/seafield/internal/access"

// AcquireFile uses the same exclusive writer/readers/floors as app mounts and
// Volume moves. A delegated file account gets no generic ManageVolumes grant.
func (s State) AcquireFile(c access.Catalog, session access.Session, issuer access.Issuer, at int64, expected uint64, id string, generation uint64, name, method string) (State, Consumer, error) {
	if c.AuthorizeVolumeFile(session, s.d.Scope.Cluster, issuer, at, s.d.Scope.Tenant, s.d.Scope.App, s.d.Scope.ID, name, method, s.d.Owner.Node) != nil {
		return s, Consumer{}, access.ErrDenied
	}
	writable := method == "volume-file-put" || method == "volume-file-delete"
	return s.acquireAuthorized(expected, id, generation, writable, s.startAllowed())
}
