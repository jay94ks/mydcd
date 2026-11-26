// SPDX-License-Identifier: Apache-2.0

package mydc

// Image builds in mydcd's real contract (REQ-19·47, docs/reference/
// image-build-jobs.md, image-build-contexts.md, unix-sockets.md). The Conn
// methods take and return the real control/imagebuild types unchanged.
//
// Real actions (submit; payloads are the control types):
//   - set-image-build-policy   control.ImageBuildPolicyPut, Expected = the policy Revision (0 = new)
//   - delete-image-build-policy control.ImageBuildSelection{Tenant}, Expected = Revision
//   - put-build-context        control.ImageBuildContextPut, Expected = the context Revision
//   - delete-build-context     control.ImageBuildSelection, Expected = Revision
//   - delete-build-version     control.ImageBuildVersionSelection, Expected = the version Number
//   - begin-image-build        control.ImageBuildJobStart from image-build-job-plan, Expected 0
//   - cancel-image-build       control.ImageBuildSelection, Expected = the job Revision
//   - delete-image-build-job   control.ImageBuildSelection (ended job), Expected = Revision
//   - prune-build-cache        control.ImageBuildCachePruneChange, Expected 0; accepted is not
//     done: progress is image-builds Part cache-prunes.
//   - begin-build-zip-upload   control.ImageBuildUploadBegin, Expected 0 (root CAS)
//   - put-build-zip-part       control.ImageBuildUploadPart{Receipt from PutBuildZIPPart},
//     Expected = the upload Revision
//   - upload-build-zip         control.ImageBuildZIPConsume{Fact from SealBuildZIP},
//     Expected = the upload Revision
//   - abort-build-zip-upload   control.ImageBuildUploadSelection, Expected = the upload Revision
//     (fake_build_zip_real.go)
//
// put-build-context, delete-build-context, delete-build-version and
// prune-build-cache keep their old names (builds.go) with these payloads.
// delete-build-context is refused while versions remain.
const (
	ActionSetImageBuildPolicy    = "set-image-build-policy"
	ActionDeleteImageBuildPolicy = "delete-image-build-policy"
	ActionBeginImageBuild        = "begin-image-build"
	ActionCancelImageBuild       = "cancel-image-build"
	ActionDeleteImageBuildJob    = "delete-image-build-job"
	// publish-build-draft: control.ImageBuildDraftPublish{Tenant, Context,
	// Frozen} from FreezeBuildDraft, Expected = the freeze plan's Revision;
	// signed by the plan's Creator. The frozen draft becomes the next version.
	ActionPublishBuildDraft = "publish-build-draft"
)

// Real job phases (ImageBuildJobView.Phase) and result codes (JobResult.Code).
const (
	ImageBuildQueued    = "queued"
	ImageBuildRunning   = "running"
	ImageBuildUnknown   = "unknown"
	ImageBuildSucceeded = "succeeded"
	ImageBuildFailed    = "failed"
	ImageBuildCancelled = "cancelled"
)
