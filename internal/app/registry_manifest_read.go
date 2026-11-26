// SPDX-License-Identifier: Apache-2.0

package app

import (
	"context"

	oci "github.com/google/go-containerregistry/pkg/registry"
	"github.com/jay94ks/mydcd/internal/cluster/control"
	"github.com/jay94ks/mydcd/internal/registryclient"
)

// The original owner lock joins this bounded metadata read with quiesce and
// Store close. The caller already holds its current quorum/read authority.
// Recovery can read a retained live Store with its listener stopped; it never
// starts a server, reopens a closed DB or borrows a second Volume writer.
func (r *Runtime) readRegistryManifest(ctx context.Context, run control.RegistryRunRef, repository, target string, serving bool) (oci.ManifestData, error) {
	r.registryMu.Lock()
	defer r.registryMu.Unlock()
	row, ok := r.registryRecords[run.Spec.Key()]
	live := r.registrySessions[run.Spec.Key()]
	if !ok || row.Run == nil || !control.SameRegistryReadRun(*row.Run, run) || row.IOClosed || live == nil || live.store == nil || live.store.Metadata == nil || serving && (row.Phase != "serving" || live.server == nil) {
		return oci.ManifestData{}, &registryclient.Error{Code: "UNAVAILABLE"}
	}
	return live.store.Metadata.GetManifest(ctx, repository, target)
}
