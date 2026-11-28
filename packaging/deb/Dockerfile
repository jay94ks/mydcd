# SPDX-License-Identifier: Apache-2.0
# Image that turns the built binaries into .deb files (dpkg-deb) and checks
# them with lintian. Only the .deb files leave it.
#   docker build -t sfc-pkg-deb packaging/deb
FROM ubuntu:24.04@sha256:562111b88caa79c71391c0c4d3c2114a7d5c35915c20561fd893cb1e07929e6b
RUN apt-get update \
	&& apt-get install -y --no-install-recommends dpkg-dev git lintian python3 \
	&& rm -rf /var/lib/apt/lists/*
