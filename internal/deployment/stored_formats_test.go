// SPDX-License-Identifier: Apache-2.0

package deployment

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// testdata/stored holds app.yaml files exactly as a running cluster stored
// them (Raft keeps app sources and sfcd parses them again at start). They
// are never edited. A PR that changes app.yaml so one no longer parses lists
// it in reinitRequired, and says "재초기화 필요" at the top of its
// description: clusters made before it must be re-initialized (no
// compatibility code before 0.1.0).
var reinitRequired = map[string]string{
	"lab-c1370ba0-app.yaml": "#910 x-sfc.ingress is a route list; A3' x-sfc.delivery became x-sfc.cd",
}

func TestStoredAppFormatsParseOrNeedReinit(t *testing.T) {
	files, err := filepath.Glob("testdata/stored/*.yaml")
	if err != nil || len(files) == 0 {
		t.Fatal("no stored formats", err)
	}
	for _, path := range files {
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		s := strings.NewReplacer("<STABLE_DEPLOYMENT_ID>", "deploy", "<WEB_IMAGE_DIGEST>", strings.Repeat("b", 64), "<DB_IMAGE_DIGEST>", strings.Repeat("c", 64), "<REGISTRY_IMAGE_DIGEST>", strings.Repeat("d", 64), "tenant-demo", "tenant").Replace(string(raw))
		_, err = ParseCompose([]byte(s))
		name := filepath.Base(path)
		why, reinit := reinitRequired[name]
		switch {
		case reinit && err == nil:
			t.Errorf("%s parses again; drop it from reinitRequired (%s)", name, why)
		case !reinit && err != nil:
			t.Errorf("%s no longer parses (%v): a cluster that stored it cannot start; list it in reinitRequired and mark the PR 재초기화 필요", name, err)
		}
	}
}
