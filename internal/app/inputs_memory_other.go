// SPDX-License-Identifier: Apache-2.0

//go:build !linux

package app

import "errors"

func mountInputMemory(string) error {
	return errors.New("app secret values need a Linux tmpfs")
}
