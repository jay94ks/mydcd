// SPDX-License-Identifier: Apache-2.0

package server

// maxBuildZipWeb: the largest zip the web takes in one request body (PUT
// .../zip). Bigger contexts go through the chunked upload
// (build_zip_upload.go), so a request never holds more than this in memory.
const maxBuildZipWeb = 8 << 20

const maxBuildFile = 1 << 20

type actionBody struct {
	Action string
	Req    any
}
