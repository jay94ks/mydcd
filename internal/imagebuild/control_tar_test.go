// SPDX-License-Identifier: Apache-2.0

package imagebuild

import (
	"archive/tar"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"testing"
)

func TestControlTARSeparatesAuthorizedSecretMaterialAndNeverSerializesValues(t *testing.T) {
	spec, _ := testJobSpec(t)
	ref := SecretMount{ID: "signing", Realm: "tenant", Secret: "key", Key: "private"}
	spec.Context.Secrets = []SecretMount{ref}
	value := SecretValue{Reference: ref, Value: []byte("ephemeral-private-value")}
	if _, err := json.Marshal(value); err == nil {
		t.Fatal("secret entered a JSON journal")
	}
	if bytes.Contains([]byte(fmt.Sprintf("%+v %#v", value, value)), value.Value) {
		t.Fatal("incidental formatting exposed secret")
	}
	var body bytes.Buffer
	if err := writeControlTAR(context.Background(), &body, spec, nil, []SecretValue{value}); err != nil {
		t.Fatal(err)
	}
	r := tar.NewReader(bytes.NewReader(body.Bytes()))
	seen := map[string]bool{}
	for {
		h, err := r.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		data, err := io.ReadAll(r)
		if err != nil || seen[h.Name] {
			t.Fatal("invalid/duplicate control entry", err)
		}
		seen[h.Name] = true
		switch h.Name {
		case "source-policy.json":
			if h.Uid != 0 || h.Mode != 0444 || !json.Valid(data) || bytes.Contains(data, value.Value) {
				t.Fatal("public policy contains private material")
			}
		case "secrets/":
			if h.Typeflag != tar.TypeDir || h.Mode != 0500 || h.Uid != 1000 {
				t.Fatal("broadened secret directory")
			}
		case "secrets/signing":
			if h.Mode != 0400 || h.Uid != 1000 || h.Gid != 1000 || !bytes.Equal(data, value.Value) {
				t.Fatal("wrong secret scope/owner")
			}
		default:
			t.Fatal("secret mixed with context/output", h.Name)
		}
	}
	if len(seen) != 3 {
		t.Fatal("missing control entries")
	}
	for _, values := range [][]SecretValue{nil, {value, value}, {{Reference: SecretMount{ID: "signing", Realm: "other", Secret: "key", Key: "private"}, Value: value.Value}}, {{Reference: ref, Value: make([]byte, (128<<10)+1)}}} {
		body.Reset()
		if err := writeControlTAR(context.Background(), &body, spec, nil, values); err == nil || body.Len() != 0 {
			t.Fatal("missing/different/oversized approval material emitted archive")
		}
	}
	body.Reset()
	if err := writeControlTAR(context.Background(), &body, spec, nil, []SecretValue{{Reference: ref}}); err != nil {
		t.Fatal("approved empty Secret value was treated as missing", err)
	}
}
