# SPDX-License-Identifier: Apache-2.0

FROM scratch
COPY rootfs/ /
USER 10001:10001
WORKDIR /work
ENTRYPOINT ["/usr/local/bin/lifecycle-compiler"]
