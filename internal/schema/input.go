// SPDX-License-Identifier: Apache-2.0

package schema

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"unicode/utf8"
)

var ErrInput = errors.New("invalid or ambiguous metadata input")

// Input accepts whitespace and omitted zero fields at the human file boundary.
// Wire/database Decode stays canonical. Case aliases and duplicate/unknown keys
// are rejected rather than silently normalized into a different instruction.
func Input[T any](raw []byte) (T, error) {
	return InputLimit[T](raw, 32<<10)
}

// InputLimit keeps the same strict metadata grammar for bounded binary-part envelopes.
// Ordinary human metadata retains the 32KiB Input limit.
func InputLimit[T any](raw []byte, limit int) (T, error) {
	var value T
	if limit < 1 || limit > 64<<10 || len(raw) == 0 || len(raw) > limit || !utf8.Valid(raw) {
		return value, ErrInput
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	budget := 4096
	if inputTokens(d, 0, &budget) != nil || d.Decode(new(any)) != io.EOF {
		return value, ErrInput
	}
	d = json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(&value) != nil {
		return value, ErrInput
	}
	canonical, err := json.Marshal(value)
	if err != nil {
		return value, ErrInput
	}
	var supplied, normalized any
	if json.Unmarshal(raw, &supplied) != nil || json.Unmarshal(canonical, &normalized) != nil || !inputKeys(supplied, normalized) {
		return value, ErrInput
	}
	return value, nil
}

func inputTokens(d *json.Decoder, depth int, budget *int) error {
	*budget--
	if depth > 32 || *budget < 0 {
		return ErrInput
	}
	token, err := d.Token()
	if err != nil {
		return err
	}
	switch token {
	case json.Delim('{'):
		seen := map[string]bool{}
		for d.More() {
			key, err := d.Token()
			name, ok := key.(string)
			if err != nil || !ok || seen[name] {
				return ErrInput
			}
			seen[name] = true
			if inputTokens(d, depth+1, budget) != nil {
				return ErrInput
			}
		}
		end, err := d.Token()
		if err != nil || end != json.Delim('}') {
			return ErrInput
		}
	case json.Delim('['):
		for d.More() {
			if inputTokens(d, depth+1, budget) != nil {
				return ErrInput
			}
		}
		end, err := d.Token()
		if err != nil || end != json.Delim(']') {
			return ErrInput
		}
	case json.Delim('}'), json.Delim(']'):
		return ErrInput
	}
	return nil
}

func inputKeys(supplied, normalized any) bool {
	switch from := supplied.(type) {
	case map[string]any:
		to, ok := normalized.(map[string]any)
		if !ok {
			return false
		}
		for k, v := range from {
			n, exists := to[k]
			if !exists || !inputKeys(v, n) {
				return false
			}
		}
	case []any:
		to, ok := normalized.([]any)
		if !ok || len(from) != len(to) {
			return false
		}
		for i, v := range from {
			if !inputKeys(v, to[i]) {
				return false
			}
		}
	}
	return true
}
