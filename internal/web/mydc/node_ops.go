// SPDX-License-Identifier: Apache-2.0

package mydc

import (
	"github.com/jay94ks/mydcd/internal/cluster/control"
	"github.com/jay94ks/mydcd/internal/imagecache"
)

// REQ-11 (mock): incident-response actions that were missing. Already
// present elsewhere: restart-task, pause-/resume-app-cd,
// stop-/start-registry, a rollback is begin-app with an earlier version
// (AppRevision.Kind "cd" marks versions CD applied, AcceptedAt is when).
// Added here: cordon/uncordon a server, tunnel links and reconnect, and a
// planned prune of a server's unused images. All are typed actions, so
// they can go in a REQ-9 allow list.

const (
	ActionCordonNode      = "cordon-node"
	ActionUncordonNode    = "uncordon-node"
	ActionReconnectTunnel = "reconnect-tunnel"
	ActionPruneNodeImages = "prune-node-images"
	InputNodeCordoned     = "NODE_CORDONED"
)

// NodeCordon: cordon-node's payload (control.NodeCordonChange{ID,
// Reason?}: Reason at most 256 characters, one line); uncordon-node takes
// NodeSelection{ID}. Expected = the server's scheduling revision. A
// cordoned server keeps its tasks; a plan or deploy that would put a new
// task there is refused with InputCode NODE_CORDONED.
type NodeCordon = control.NodeCordonChange

// Image cache cleanup (node-image-cache.md, system admin): image-cache-plan
// lists or selects (≤ 8 full IDs) a server's images with their container
// and reference counts; prune-node-images (Expected 0, root RootFor:
// ImageCacheKey) carries ImageCacheChange{Operation, Plan} with a selection
// plan whose images are all unused; image-cache-status follows the job.
type (
	ImageCacheQuery  = imagecache.Query
	ImageCachePlan   = imagecache.Plan
	ImageCacheImage  = imagecache.Image
	ImageCacheChange = imagecache.Change
	ImageCacheStatus = control.ImageCacheStatus
)

// ImageCacheMaxImages: images in one plan page or one selection.
const ImageCacheMaxImages = imagecache.MaxImages
