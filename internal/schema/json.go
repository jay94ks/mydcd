// SPDX-License-Identifier: Apache-2.0

// Package schema decodes canonical schema-1 module values. Canonical comparison
// rejects duplicate fields and ambiguous spellings in addition to unknown keys.
package schema

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
)

func Decode[T any](b []byte) (T, error) {
	var value T
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if err := d.Decode(&value); err != nil {
		return value, err
	}
	if d.Decode(new(any)) != io.EOF {
		return value, errors.New("trailing module value")
	}
	canonical, err := json.Marshal(value)
	if err != nil || !bytes.Equal(canonical, b) {
		return value, errors.New("noncanonical module value")
	}
	return value, nil
}
