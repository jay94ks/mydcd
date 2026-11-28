# SPDX-License-Identifier: Apache-2.0
# Image that turns the built binaries into .rpm files (rpmbuild -bb) and
# checks them with rpmlint. Only the .rpm files leave it.
#   docker build -t sfc-pkg-rpm packaging/rpm
FROM fedora:43@sha256:f01112b9a1f1d0504ad962d9adfa401425033f8ab067e0a821904ebdde5b8ca5
RUN dnf install -y --setopt=install_weak_deps=False git rpm-build rpmlint python3 \
	&& dnf clean all
