# SPDX-License-Identifier: Apache-2.0

# mydc-web container. Build from the repository root:
#   docker build -f apps/mydc-web/Dockerfile -t mydc-web .
# In a development checkout the 3rd-party submodule must be checked out and
# patched first (3rd-party/README.md); the public source tree ships it patched.
# The build does not fetch or patch anything.

# 1) Web UI (skipped when apps/mydc-web/web has no package.json yet)
FROM node:22.11.0-bookworm-slim AS ui
WORKDIR /src
COPY apps/mydc-web/ /src/apps/mydc-web/
RUN set -eu; mkdir -p /out; \
    if [ -f apps/mydc-web/web/package.json ]; then \
      cd apps/mydc-web/web && npm ci && npm run build && cp -a dist/. /out/; \
    fi

# 2) Go daemon (same module as mydcd/mydc, separate binary)
FROM golang:1.27.3-bookworm AS go
ENV GOTOOLCHAIN=local CGO_ENABLED=0
WORKDIR /src
COPY go.mod go.sum ./
COPY 3rd-party/ 3rd-party/
RUN go mod download
COPY . .
COPY --from=ui /out/ apps/mydc-web/ui/dist/
RUN go build -trimpath -ldflags="-s -w" -o /out/mydc-web ./cmd/mydc-web

# 3) Runtime
FROM gcr.io/distroless/static-debian12
COPY --from=go /out/mydc-web /usr/local/bin/mydc-web
# mydc.sock is 0600: run the container with the UID that owns it
# (docker run --user <uid>). The UID is not a management credential; every
# cluster call uses the logged-in user's own MYDCP session.
VOLUME ["/var/lib/mydc-web"]
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/mydc-web"]
