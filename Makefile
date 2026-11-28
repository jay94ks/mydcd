# SPDX-License-Identifier: Apache-2.0

# Build, test and release helpers for Seafield Cluster.
#   make            build bin/sfcd, bin/sfcli, bin/sfc-web (with the web UI)
#   make test       unit tests
#   make lint       gofmt, go vet, SPDX headers, documentation links
#   make dist       packages, notices, SBOM and checksums in dist/
#   make packages   deb, rpm and tar.gz for GOARCH in dist/, built in Docker
#                   from packaging/ (sfcd, sfcli, Seafield Engine with its own
#                   containerd and runc; sfc-web-image when dist/ holds the
#                   web bundle from make webbundle)
#   make featurenotes  feature-set table for the release notes in
#                   dist/FEATURES.md (PREV=<previous release's FEATURES.txt>)
#   make webbundle  signed sfc-web cluster app image bundle in dist/ (needs
#                   docker buildx and SFC_RELEASE_KEY, the release key)
#   make install    install sfcd, sfcli and the sfcli agent guide under PREFIX

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

# Package version: v0.1.0 is 0.1.0; a development VERSION (no tag) sorts
# before any release, 0.0.0~dev.<describe>.
PKGVERSION = $(shell echo '$(VERSION:v%=%)' | sed -E -e 's/^([^0-9])/0.0.0~dev.\1/' -e 's/-/~/g')
PKGBUILD   := dist/pkg-$(GOARCH)
WEBIMAGE   ?= $(wildcard dist/sfc-web-image_$(VERSION)_$(GOOS)_$(GOARCH).tar.gz)
# Extra docker flags for a network that needs them (a proxy, --network host).
PKGDOCKERFLAGS ?=
PKGRUN      = docker run --rm $(PKGDOCKERFLAGS) --platform $(GOOS)/$(GOARCH) --user $$(id -u):$$(id -g) \
              -e HOME=/tmp -e SOURCE_DATE_EPOCH=$$(git log -1 --format=%ct) \
              -v $(CURDIR):/src -w /src

.PHONY: all build ui test lint notices sbom dist packages featurenotes webbundle install clean

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

# in-toto's LICENSE files are a short Apache-2.0 header that go-licenses
# cannot classify, so they are copied by hand instead of failing the save.
NOTICE_BYHAND := github.com/in-toto/attestation github.com/in-toto/in-toto-golang

notices:
	@mkdir -p dist
	cd $(WEB) && npm ci
	go run github.com/google/go-licenses/v2@v2.0.1 report ./cmd/... --ignore github.com/in-toto > dist/THIRD_PARTY_GO.csv
	go run github.com/google/go-licenses/v2@v2.0.1 save ./cmd/... --ignore github.com/in-toto --save_path dist/third_party --force
	for m in $(NOTICE_BYHAND); do \
	  install -D -m 0644 "$$(go list -m -f '{{.Dir}}' $$m)/LICENSE" dist/third_party/$$m/LICENSE && \
	  echo "$$m,https://$$m/blob/HEAD/LICENSE,Apache-2.0" >> dist/THIRD_PARTY_GO.csv || exit 1; \
	done
	python3 -I tools/publish/notices.py dist/third_party $(WEB)/package-lock.json > dist/THIRD_PARTY_NOTICES

sbom: packages
	syft dir:$(PKGBUILD)/bin -o spdx-json=dist/sfc_$(VERSION)_$(GOOS)_$(GOARCH).spdx.json

dist: packages sbom
	cd dist && sha256sum *.deb *.rpm *.tar.gz *.spdx.json > SHA256SUMS

# Every binary is built inside packaging/builder, then packaged inside
# packaging/deb and packaging/rpm; only the package files come out
# (devel/design/install-packages.md 2). THIRD_PARTY_NOTICES (make notices)
# goes into each package with the engine's notices.
packages: notices
	docker build $(PKGDOCKERFLAGS) --platform $(GOOS)/$(GOARCH) -q -t sfc-pkg-builder packaging/builder
	docker build $(PKGDOCKERFLAGS) --platform $(GOOS)/$(GOARCH) -q -t sfc-pkg-deb packaging/deb
	docker build $(PKGDOCKERFLAGS) --platform $(GOOS)/$(GOARCH) -q -t sfc-pkg-rpm packaging/rpm
	rm -rf dist/pkg-$(GOARCH)
	mkdir -p $(PKGBUILD)
	cp dist/THIRD_PARTY_NOTICES $(PKGBUILD)/
	$(PKGRUN) sfc-pkg-builder packaging/build.sh $(PKGBUILD) $(VERSION)
	$(PKGRUN) sfc-pkg-deb packaging/deb/build.sh $(PKGBUILD) $(PKGVERSION) $(GOARCH) dist $(WEBIMAGE)
	$(PKGRUN) sfc-pkg-rpm packaging/rpm/build.sh $(PKGBUILD) $(PKGVERSION) $(GOARCH) dist $(WEBIMAGE)
	$(PKGRUN) sfc-pkg-deb packaging/tar.sh $(PKGBUILD) $(VERSION) $(GOARCH) dist $(WEBIMAGE)

# Every release announces its feature-set changes and version ranges in a
# table (devel/design/upgrades.md 3-1). FEATURES.txt is this build's names,
# attached to the release so the next one can compare (PREV).
featurenotes:
	@mkdir -p dist
	go run ./tools/featurenotes -list > dist/FEATURES.txt
	go run ./tools/featurenotes $(if $(PREV),-prev '$(PREV)') > dist/FEATURES.md

# The sfc-web cluster app image for one platform, as the bundle sfcd reads
# from <prefix>/lib/sfc/images/sfc-web/: an OCI layout plus its release
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

# The archive's layout without the engine: the real sfcd in lib/sfc/bin,
# where sfed accepts it, and a link in bin (devel/design/install-packages.md 4).
install:
	install -d $(DESTDIR)$(PREFIX)/bin $(DESTDIR)$(PREFIX)/lib/sfc/bin $(DESTDIR)$(PREFIX)/share/sfc
	install -m 0755 bin/sfcd $(DESTDIR)$(PREFIX)/lib/sfc/bin/
	ln -sfn ../lib/sfc/bin/sfcd $(DESTDIR)$(PREFIX)/bin/sfcd
	install -m 0755 bin/sfcli $(DESTDIR)$(PREFIX)/bin/
	install -m 0644 $(SKILL) $(DESTDIR)$(PREFIX)/share/sfc/SKILL.md

clean:
	rm -rf bin dist
