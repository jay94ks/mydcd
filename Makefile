# SPDX-License-Identifier: Apache-2.0

# Build, test and release helpers for MyDC.
#   make            build bin/mydcd, bin/mydc, bin/mydc-web (with the web UI)
#   make test       unit tests
#   make lint       gofmt, go vet, SPDX headers, documentation links
#   make dist       release archives, checksums, notices and SBOM in dist/
#   make install    install binaries and the mydc agent guide under PREFIX

VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
GOOS    ?= linux
GOARCH  ?= $(shell go env GOARCH)
LDFLAGS := -s -w -X main.version=$(VERSION)
GO      := CGO_ENABLED=0 GOOS=$(GOOS) GOARCH=$(GOARCH) go
WEB     := apps/mydc-web/web
BINS    := mydcd mydc mydc-web
PREFIX  ?= /usr/local
# Agent guide for the mydc CLI. `mydc --help` looks next to the executable,
# then at <bin>/../share/mydc/SKILL.md (see docs/cli/README.md).
SKILL   := cmd/mydc/SKILL.md

.PHONY: all build ui test lint notices sbom dist install clean

all: build

ui:
	cd $(WEB) && npm ci && npm run build
	rm -rf apps/mydc-web/ui/dist && mkdir -p apps/mydc-web/ui/dist
	cp -a $(WEB)/dist/. apps/mydc-web/ui/dist/
	touch apps/mydc-web/ui/dist/.keep

build: ui
	@mkdir -p bin
	$(foreach b,$(BINS),$(GO) build -trimpath -ldflags "$(LDFLAGS)" -o bin/$(b) ./cmd/$(b) &&) true

test:
	go test -p 2 ./...
	cd $(WEB) && npm ci && npm test

lint:
	@test -z "$$(gofmt -l cmd internal lifecycle tests apps)" || (gofmt -l cmd internal lifecycle tests apps; exit 1)
	go vet ./...
	python3 -I tools/check-spdx.py
	python3 -I tools/check-links.py

notices:
	@mkdir -p dist
	go run github.com/google/go-licenses/v2@v2.0.1 report ./cmd/... > dist/THIRD_PARTY_GO.csv
	go run github.com/google/go-licenses/v2@v2.0.1 save ./cmd/... --save_path dist/third_party --force
	python3 -I tools/publish/notices.py dist/third_party $(WEB)/package-lock.json > dist/THIRD_PARTY_NOTICES

sbom: build
	@mkdir -p dist
	syft dir:bin -o spdx-json=dist/mydc_$(VERSION)_$(GOOS)_$(GOARCH).spdx.json

dist: build notices sbom
	rm -rf dist/stage && mkdir -p dist/stage/mydc_$(VERSION)
	cp bin/mydcd bin/mydc bin/mydc-web $(SKILL) LICENSE NOTICE dist/THIRD_PARTY_NOTICES dist/stage/mydc_$(VERSION)/
	tar -C dist/stage -czf dist/mydc_$(VERSION)_$(GOOS)_$(GOARCH).tar.gz mydc_$(VERSION)
	rm -rf dist/stage
	cd dist && sha256sum *.tar.gz *.spdx.json > SHA256SUMS

install:
	install -d $(DESTDIR)$(PREFIX)/bin $(DESTDIR)$(PREFIX)/share/mydc
	install -m 0755 bin/mydcd bin/mydc $(DESTDIR)$(PREFIX)/bin/
	install -m 0644 $(SKILL) $(DESTDIR)$(PREFIX)/share/mydc/SKILL.md

clean:
	rm -rf bin dist
