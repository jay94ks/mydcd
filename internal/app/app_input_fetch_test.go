// SPDX-License-Identifier: Apache-2.0

package app

import (
	"bytes"
	"encoding/json"
	"errors"
	"testing"

	"github.com/jay94ks/mydcd/internal/mydcp"
	"github.com/jay94ks/mydcd/internal/secrets"
)

func TestPrivateInputFetchEncodingDoesNotWidenOrdinarySerialization(t *testing.T) {
	v := secrets.Fetched{Secret: "data", Reference: secrets.Reference{Profile: "values", Object: "tenant/data", Revision: 1, Keys: []string{"PASSWORD"}}, Values: map[string][]byte{"PASSWORD": []byte("private-wire-value")}}
	defer clear(v.Values["PASSWORD"])
	if _, err := json.Marshal(v); !errors.Is(err, secrets.ErrPrivateMaterial) {
		t.Fatal("ordinary private guard changed", err)
	}
	if _, err := json.Marshal(appInputFetchResponse{Schema: 1, ReadSet: [32]byte{1}, Value: v}); !errors.Is(err, secrets.ErrPrivateMaterial) {
		t.Fatal("ordinary response encoding leaked private value", err)
	}
	body, err := encodeAppInputFetchResponse([32]byte{1}, v)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(body)
	var got appInputFetchResponse
	if json.Unmarshal(body, &got) != nil || got.ReadSet != ([32]byte{1}) || got.Value.Secret != v.Secret || !bytes.Equal(got.Value.Values["PASSWORD"], v.Values["PASSWORD"]) {
		t.Fatal("explicit private wire round trip")
	}
	defer clear(got.Value.Values["PASSWORD"])
	large := secrets.Fetched{Secret: "data", Values: map[string][]byte{"PASSWORD": make([]byte, 128<<10)}}
	if _, err = encodeAppInputFetchResponse([32]byte{1}, large); err != mydcp.ErrBudget {
		t.Fatal("private payload bound bypass", err)
	}
}

func TestPrivateInputFetchResponseRejectsDuplicateAndUnknownFields(t *testing.T) {
	v := secrets.Fetched{Secret: "data", Values: map[string][]byte{"PASSWORD": []byte("private-wire-value")}}
	defer clear(v.Values["PASSWORD"])
	body, err := encodeAppInputFetchResponse([32]byte{1}, v)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(body)
	got, err := decodeAppInputFetchResponse(body)
	if err != nil {
		t.Fatal("canonical private response", err)
	}
	for _, v := range got.Value.Values {
		clear(v)
	}
	for _, bad := range [][]byte{bytes.Replace(body, []byte(`"Schema":1`), []byte(`"Schema":1,"Schema":1`), 1), bytes.Replace(body, []byte(`"Schema":1`), []byte(`"Schema":1,"Unrecognized":true`), 1), append(append([]byte(nil), body...), byte('\n'))} {
		_, err := decodeAppInputFetchResponse(bad)
		clear(bad)
		if err == nil {
			t.Fatal("noncanonical private response accepted")
		}
	}
}
