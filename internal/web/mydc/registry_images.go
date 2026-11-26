// SPDX-License-Identifier: Apache-2.0

package mydc

// REQ-18 registry maintenance actions (docs/reference/registry-maintenance.md).
// RegistryImage is the fake's own built-in registry row (fixture Images).

// Payload is the plan's control.RegistryMaintenanceChange with Operation set,
// Expected the plan's Expected (prune: the preview's Plan).
const (
	ActionDeleteRegistryImage = "delete-registry-image"
	ActionGCRegistry          = "gc-registry"
	ActionPruneRegistryImages = "prune-registry-images"
)

// ResultImageInUse: provisional web-side code; ResultErrorCode gives
// "image-in-use". mydcd reports an image in use as the job result
// IMAGE_IN_USE (RegistryMaintenanceStatus), so the fake never returns it.
const (
	ResultImageInUse ResultCode = 102
	ImageInUse                  = "image-in-use"
)

type RegistryImage struct {
	Registry, Repository, Digest string
	Tags                         []string // empty = untagged
	Bytes                        uint64   // manifest + layers
	PushedAt                     int64
}
