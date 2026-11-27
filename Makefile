# SPDX-License-Identifier: Apache-2.0

# Build, test and release helpers for Seafield Cluster.
#   make            build bin/sfcd, bin/sfcli, bin/sfc-web (with the web UI)
#   make test       unit tests
#   make lint       gofmt, go vet, SPDX headers, documentation links
#   make dist       release archives, checksums, notices and SBOM in dist/
#   make webbundle  signed sfc-web cluster app image bundle in dist/ (needs
#                   docker buildx and SFC_RELEASE_KEY, the release key)
#   make install    install binaries and the sfcli agent guide under PREFIX

VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
GOOS    ?= linux
GOARCH  ?= $(shell go env GOARCH)
# A release tag vX.Y.Z puts build number Z into the binaries; X.Y must equal
# internal/buildinfo's Major.Minor or the build stops. Any other VERSION is a
# development build (devel/design/upgrades.md 3-6).
VERSIONFLAGS = $$(go run ./tools/buildversion '$(VERSION)')
GO      := CGO_ENABLED=0 GOOS=$(GOOS) GOARCH=$(GOARCH) go
WEB     := apps/sfc-web/web
BINS    := sfcd sfcli sfc-web
PREFIX  ?= /usr/local
# Agent guide for the sfcli CLI. `sfcli --help` looks next to the executable,
# then at <bin>/../share/sfc/SKILL.md (see docs/cli/README.md).
SKILL   := cmd/sfcli/SKILL.md

.PHONY: all build ui test lint notices sbom dist webbundle install clean

all: build

ui:
	cd $(WEB) && npm ci && npm run build
	rm -rf apps/sfc-web/ui/dist && mkdir -p apps/sfc-web/ui/dist
	cp -a $(WEB)/dist/. apps/sfc-web/ui/dist/
	touch apps/sfc-web/ui/dist/.keep

build: ui
	@mkdir -p bin
	flags="$(VERSIONFLAGS)" && \
	$(foreach b,$(BINS),$(GO) build -trimpath -ldflags "-s -w $$flags" -o bin/$(b) ./cmd/$(b) &&) true

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
	syft dir:bin -o spdx-json=dist/sfc_$(VERSION)_$(GOOS)_$(GOARCH).spdx.json

dist: build notices sbom
	rm -rf dist/stage && mkdir -p dist/stage/sfc_$(VERSION)
	cp bin/sfcd bin/sfcli bin/sfc-web $(SKILL) LICENSE NOTICE dist/THIRD_PARTY_NOTICES dist/stage/sfc_$(VERSION)/
	tar -C dist/stage -czf dist/sfc_$(VERSION)_$(GOOS)_$(GOARCH).tar.gz sfc_$(VERSION)
	rm -rf dist/stage
	cd dist && sha256sum *.tar.gz *.spdx.json > SHA256SUMS

# The sfc-web cluster app image for one platform, as the bundle sfcd reads
# from /usr/local/lib/sfc/images/sfc-web/: an OCI layout plus its release
# manifest signed with SFC_RELEASE_KEY, checked against the keys built into
# sfcd (devel/design/cluster-apps.md 3.3).
webbundle:
	rm -rf dist/images && mkdir -p dist/images/sfc-web
	flags="$(VERSIONFLAGS)" && \
	docker buildx build -f apps/sfc-web/Dockerfile --platform $(GOOS)/$(GOARCH) \
	  --build-arg "SFC_VERSION_FLAGS=$$flags" \
	  --provenance=false --sbom=false -o type=oci,dest=dist/sfc-web.oci.tar .
	tar -xf dist/sfc-web.oci.tar -C dist/images/sfc-web && rm dist/sfc-web.oci.tar
	go run ./tools/clusterapp-bundle sign -key-env SFC_RELEASE_KEY -app web -version $(VERSION:v%=%) -bundle dist/images/sfc-web
	go run ./tools/clusterapp-bundle verify -builtin -app web -bundle dist/images/sfc-web
	tar -C dist/images -czf dist/sfc-web-image_$(VERSION)_$(GOOS)_$(GOARCH).tar.gz sfc-web
	rm -rf dist/images

install:
	install -d $(DESTDIR)$(PREFIX)/bin $(DESTDIR)$(PREFIX)/share/sfc
	install -m 0755 bin/sfcd bin/sfcli $(DESTDIR)$(PREFIX)/bin/
	install -m 0644 $(SKILL) $(DESTDIR)$(PREFIX)/share/sfc/SKILL.md

clean:
	rm -rf bin dist
