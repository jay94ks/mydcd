// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"errors"
	"os"

	"github.com/jay94ks/mydcd/internal/identity"
)

// walletPasswordFromEnv reads the wallet password for scripts from the file
// named by MYDC_WALLET_PASSWORD_FILE. The file must be a regular file no
// wider than mode 0600; one trailing newline is removed. ok is false when
// the variable is unset.
func walletPasswordFromEnv() (password []byte, ok bool, err error) {
	path := os.Getenv("MYDC_WALLET_PASSWORD_FILE")
	if path == "" {
		return nil, false, nil
	}
	info, err := os.Lstat(path)
	if err != nil {
		return nil, true, err
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0o177 != 0 {
		return nil, true, errors.New("MYDC_WALLET_PASSWORD_FILE must be a regular file with mode 0600")
	}
	if info.Size() > 1025 {
		return nil, true, identity.ErrCredential
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, true, err
	}
	value := bytes.TrimSuffix(raw, []byte{'\n'})
	if len(value) < 1 || len(value) > 1024 || bytes.ContainsAny(value, "\r\n\x00") {
		clear(raw)
		return nil, true, identity.ErrCredential
	}
	return value, true, nil
}
