// SPDX-License-Identifier: Apache-2.0

package services

// Clock is the DNS/route observation clock. It is never consensus input.
type Clock struct {
	Boot       [32]byte
	Wall, Mono int64
	Certain    bool
}
