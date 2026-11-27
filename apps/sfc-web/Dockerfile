# SPDX-License-Identifier: Apache-2.0

# sfc-web container. Build from the repository root:
#   docker build -f apps/sfc-web/Dockerfile -t sfc-web .
# In a development checkout the 3rd-party submodule must be checked out and
# patched first (3rd-party/README.md); the public source tree ships it patched.
# The build does not fetch or patch anything.

# 1) Web UI (skipped when apps/sfc-web/web has no package.json yet)
FROM node:22.11.0-bookworm-slim AS ui
WORKDIR /src
COPY apps/sfc-web/ /src/apps/sfc-web/
RUN set -eu; mkdir -p /out; \
    if [ -f apps/sfc-web/web/package.json ]; then \
      cd apps/sfc-web/web && npm ci && npm run build && cp -a dist/. /out/; \
    fi

# 2) Go daemon (same module as sfcd/sfc, separate binary)
FROM golang:1.27.3-bookworm AS go
ENV GOTOOLCHAIN=local CGO_ENABLED=0
WORKDIR /src
COPY go.mod go.sum ./
COPY 3rd-party/ 3rd-party/
RUN go mod download
COPY . .
COPY --from=ui /out/ apps/sfc-web/ui/dist/
# SFC_VERSION_FLAGS: the linker flags tools/buildversion prints for a release
# tag (make webbundle passes them); empty for a development build.
ARG SFC_VERSION_FLAGS=""
RUN go build -trimpath -ldflags="-s -w ${SFC_VERSION_FLAGS}" -o /out/sfc-web ./cmd/sfc-web

# 3) Runtime
FROM gcr.io/distroless/static-debian12
COPY --from=go /out/sfc-web /usr/local/bin/sfc-web
# sfcdp.sock is 0600: run the container with the UID that owns it
# (docker run --user <uid>). The UID is not a management credential; every
# cluster call uses the logged-in user's own SFCP session.
VOLUME ["/var/lib/sfc-web"]
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/sfc-web"]
