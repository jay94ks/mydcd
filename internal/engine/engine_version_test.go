// SPDX-License-Identifier: Apache-2.0

package engine

import (
	"errors"
	"testing"
)

func TestEngineAPIMinimum(t *testing.T) {
	for _, v := range []string{"1.48", "1.52", "2.0"} {
		if err := checkEngineAPI(v); err != nil {
			t.Fatal(v, err)
		}
	}
	for _, v := range []string{"1.47", "1.41", "", "x.y"} {
		if err := checkEngineAPI(v); !errors.Is(err, ErrEngineVersion) {
			t.Fatal(v, err)
		}
	}
}
