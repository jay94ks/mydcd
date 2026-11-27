// SPDX-License-Identifier: Apache-2.0

package sfcp

import (
	"bytes"
	"encoding/json"
	"errors"
)

// ErrBodyJSON: a signed envelope body is not compact JSON, so it cannot be
// carried as itself inside the envelope.
var ErrBodyJSON = errors.New("signed body is not compact JSON")

// RawBody checks that body can be embedded in an envelope's JSON as itself
// (design O4): signed bodies are compact JSON, and embedding them saves the
// base64 that a []byte field would add. The receiver gets the exact bytes.
func RawBody(body []byte) (json.RawMessage, error) {
	var b bytes.Buffer
	if len(body) == 0 || json.Compact(&b, body) != nil || !bytes.Equal(b.Bytes(), body) {
		return nil, ErrBodyJSON
	}
	return json.RawMessage(body), nil
}

// StrictJSON decodes raw into v refusing unknown fields and trailing data.
func StrictJSON(raw []byte, v any) error {
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if err := d.Decode(v); err != nil {
		return err
	}
	if d.More() {
		return ErrFrame
	}
	return nil
}
