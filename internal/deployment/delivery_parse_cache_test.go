// SPDX-License-Identifier: Apache-2.0

package deployment

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"reflect"
	"strings"
	"sync"
	"testing"

	"gopkg.in/yaml.v3"
)

func parseTestArtifact(raw []byte) deliveryArtifact {
	return deliveryArtifact{Kind: "file", Digest: sha256.Sum256(raw), Body: raw}
}

func TestDeliveryArtifactCachePreservesInputContractAndSourceValidation(t *testing.T) {
	app := parseTestArtifact([]byte(appInputDocument()))
	for _, kind := range []string{"", "app"} {
		cold, err := parseCompose(app.Body, kind == "app")
		if err != nil {
			t.Fatal(err)
		}
		for range 2 {
			warm, err := artifactComposeKind(app, kind)
			if err != nil || !reflect.DeepEqual(cold, warm) {
				t.Fatal("cached model changed input semantics", kind, err)
			}
		}
	}
	legacy, err := yaml.Marshal(smallCompose(t))
	if err != nil {
		t.Fatal(err)
	}
	old := parseTestArtifact(legacy)
	if _, err := artifactComposeKind(old, ""); err != nil {
		t.Fatal("original contract", err)
	}
	if _, err := artifactComposeKind(old, "app"); err == nil {
		t.Fatal("warm legacy result bypassed app management boundary")
	}
	for _, mutate := range []func(*deliveryArtifact){
		func(a *deliveryArtifact) { a.Body = append(bytes.Clone(a.Body), 'x') },
		func(a *deliveryArtifact) { a.Digest[0] ^= 1 },
		func(a *deliveryArtifact) { a.Kind = "other" },
		func(a *deliveryArtifact) { a.Commit = strings.Repeat("a", 40) },
		func(a *deliveryArtifact) { a.Path = "app.yaml" },
		func(a *deliveryArtifact) { a.Kind, a.Commit, a.Path = "git", "invalid", "app.yaml" },
		func(a *deliveryArtifact) { a.Kind, a.Commit, a.Path = "git", strings.Repeat("a", 40), "../app.yaml" },
	} {
		bad := app
		mutate(&bad)
		if _, err := artifactComposeKind(bad, "app"); err == nil {
			t.Fatal("warm parse bypassed original artifact metadata/digest validation")
		}
	}
	if _, err := artifactComposeKind(app, "unknown"); err == nil {
		t.Fatal("unknown input contract accepted")
	}
}

func TestDeliveryArtifactCacheConcurrentReadersOwnTheirModels(t *testing.T) {
	raw := []byte(strings.Replace(appInputDocument(), "    command: []", "    command: []\n    dns: []\n    dns_search: []\n    healthcheck: {test: [CMD, 'true']}", 1))
	a := parseTestArtifact(raw)
	var cache artifactParseCache
	start := make(chan struct{})
	errors := make(chan error, 16)
	var wg sync.WaitGroup
	for range 16 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			for range 4 {
				c, err := cache.compose(a, "app")
				s := c.Services["web"]
				if err != nil || s.Environment["MODE"] != "app" || s.Command == nil || len(*s.Command) != 0 || s.DNS == nil || len(s.DNS) != 0 || s.DNSSearch == nil || s.Healthcheck == nil || s.Healthcheck.Test[0] != "CMD" || c.Networks["app"].Name != "shared-lan" {
					errors <- fmt.Errorf("reader ownership/explicit emptiness: %v", err)
					return
				}
				s.Environment["MODE"] = "changed"
				*s.Command = Arguments{"changed"}
				s.Healthcheck.Test[0] = "changed"
				c.Networks["app"] = ComposeNetwork{Name: "changed"}
				delete(c.Services, "web")
			}
		}()
	}
	close(start)
	wg.Wait()
	close(errors)
	for err := range errors {
		t.Error(err)
	}
	if len(cache.entries) != 1 {
		t.Fatal("same immutable input was not coalesced")
	}
}

func TestDeliveryArtifactCacheEvictionPreservesParsingAndBounds(t *testing.T) {
	var cache artifactParseCache
	a := parseTestArtifact([]byte(appInputDocument()))
	first, err := cache.compose(a, "app")
	if err != nil {
		t.Fatal(err)
	}
	for i := range artifactParseEntries + 1 {
		b := parseTestArtifact(append([]byte(fmt.Sprintf("# distinct %d\n", i)), a.Body...))
		if _, err := cache.compose(b, "app"); err != nil || len(cache.entries) > artifactParseEntries || cache.bytes > artifactParseBytes {
			t.Fatal("entry bound changed parse result", err)
		}
	}
	for i := range 3 {
		b := parseTestArtifact(append([]byte(fmt.Sprintf("# %d%s\n", i, strings.Repeat("x", 3<<20))), a.Body...))
		if _, err := cache.compose(b, "app"); err != nil || cache.bytes > artifactParseBytes {
			t.Fatal("byte bound changed parse result", err)
		}
	}
	again, err := cache.compose(a, "app")
	if err != nil || !reflect.DeepEqual(first, again) {
		t.Fatal("eviction changed semantics", err)
	}
	bad := parseTestArtifact([]byte("services: [broken]"))
	if _, err := cache.compose(bad, "app"); err == nil {
		t.Fatal("invalid source accepted")
	}
	if _, exists := cache.entries[artifactParseKey{bad.Digest, "app"}]; exists {
		t.Fatal("failed parse cached")
	}
}

func BenchmarkDeliveryArtifactParse(b *testing.B) {
	a := parseTestArtifact([]byte(appInputDocument()))
	for _, warm := range []bool{false, true} {
		b.Run(fmt.Sprint("cached=", warm), func(b *testing.B) {
			var cache artifactParseCache
			_, _ = cache.compose(a, "app")
			b.ReportAllocs()
			b.ResetTimer()
			for b.Loop() {
				var model Compose
				var err error
				if warm {
					model, err = cache.compose(a, "app")
				} else {
					model, err = parseCompose(a.Body, true)
				}
				if err != nil || len(model.Services) != 1 {
					b.Fatal(err)
				}
			}
		})
	}
}
