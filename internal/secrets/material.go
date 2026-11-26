// SPDX-License-Identifier: Apache-2.0

package secrets

import (
	"errors"
	"fmt"
	"io"
)

var ErrPrivateMaterial = errors.New("secret material cannot be JSON encoded")

// Ordinary structured logging/snapshot encoding must fail closed on these
// private staging wrappers. This is not a memory-erasure guarantee and cannot
// prevent a consumer from explicitly extracting and logging a raw value.
func (Fetched) MarshalJSON() ([]byte, error) { return nil, ErrPrivateMaterial }
func (Keyset) MarshalJSON() ([]byte, error)  { return nil, ErrPrivateMaterial }
func (Fetched) Format(s fmt.State, _ rune)   { _, _ = io.WriteString(s, "[redacted secret material]") }
func (Keyset) Format(s fmt.State, _ rune)    { _, _ = io.WriteString(s, "[redacted secret material]") }
