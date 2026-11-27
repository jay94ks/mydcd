// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"fmt"
	"io"
	"os"

	"github.com/jay94ks/seafield/internal/access"
	"github.com/jay94ks/seafield/internal/identity"
)

func readLoginSecret(input *os.File, stdin bool, diagnostic io.Writer, method access.Method) ([]byte, error) {
	if method != access.Password && method != access.Token {
		return nil, identity.ErrCredential
	}
	if !stdin {
		_, _ = fmt.Fprint(diagnostic, "Credential: ")
		value, err := identity.ReadPassword(int(input.Fd()))
		_, _ = fmt.Fprintln(diagnostic)
		return value, err
	}
	raw, err := io.ReadAll(io.LimitReader(input, 1026))
	if err != nil {
		clear(raw)
		return nil, identity.ErrCredential
	}
	value := bytes.TrimSuffix(raw, []byte{'\n'})
	if len(value) == 0 || len(value) > 1024 || bytes.ContainsAny(value, "\r\n\x00") {
		clear(raw)
		return nil, identity.ErrCredential
	}
	return value, nil
}
