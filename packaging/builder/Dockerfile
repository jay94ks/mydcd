# SPDX-License-Identifier: Apache-2.0
# Build image for the release binaries: sfcd, sfcli, Seafield Engine (sfed,
# sfe-runc) and the containerd and runc that ship with it. runc needs cgo and
# libseccomp; everything else is a static Go build. Only this Dockerfile is
# published, not the image (devel/design/install-packages.md 2).
#   docker build -t sfc-pkg-builder packaging/builder
# Go comes from the official image (pinned by digest); the rest is Ubuntu
# 24.04 LTS, the oldest supported target.
FROM golang:1.27.0-trixie@sha256:df98008ecd2b0ecc9f0a94d1b07e3564a9c92b555369b33d9b5f60d0765b2db7 AS go

FROM ubuntu:24.04@sha256:562111b88caa79c71391c0c4d3c2114a7d5c35915c20561fd893cb1e07929e6b
COPY --from=go /usr/local/go /usr/local/go
ENV PATH=/usr/local/go/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
RUN apt-get update \
	&& apt-get install -y --no-install-recommends \
		binutils ca-certificates gcc git libc6-dev libseccomp-dev linux-libc-dev make pkg-config python3 \
	&& rm -rf /var/lib/apt/lists/*
