// SPDX-License-Identifier: Apache-2.0

package imagebuild

import "encoding/hex"

func DraftRootConsumer(scope DraftScope) string {
	h := scope.Digest()
	return "imagebuild-draft/" + hex.EncodeToString(h[:])
}
func GitRootConsumer(plan GitSavePlan) string {
	h := plan.Digest()
	return "imagebuild-git/" + hex.EncodeToString(h[:])
}
func ArtifactRootConsumer(scope UploadScope) string {
	h := scope.Hash()
	return "imagebuild/" + hex.EncodeToString(h[:])
}
