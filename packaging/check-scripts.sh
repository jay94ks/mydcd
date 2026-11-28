#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# check-scripts.sh: the package definitions never remove or replace another
# package (devel/design/install-packages.md 3, X23). The base packages a host
# relies on (iproute2, isc-dhcp*, initscripts, systemd-resolved, dhcpcd-base,
# systemd-networkd) and anything that depends on them must survive any
# install, upgrade, remove or purge of ours, and are never installed by us
# either. So no package relation that can remove one, and no maintainer
# script or scriptlet that runs a package manager.
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
files=$(find "$here/deb" "$here/rpm" -type f ! -name Dockerfile ! -name '*.description')
bad=0
# Relations that make apt or dnf remove another package.
if grep -nE '^[[:space:]]*(Conflicts|Breaks|Replaces|Obsoletes|Provides)[[:space:]]*:' $files; then
	echo "check-scripts.sh: package relation that can remove another package" >&2
	bad=1
fi
# Package manager runs (install, remove, purge, autoremove) from scripts.
if grep -nwE '(apt|apt-get|aptitude|dpkg|dnf|yum|rpm|zypper)[[:space:]]+(-[^[:space:]]+[[:space:]]+)*(install|remove|purge|autoremove|erase|-[a-zA-Z]*[eP])' $files; then
	echo "check-scripts.sh: script runs a package manager" >&2
	bad=1
fi
if grep -nwE 'autoremove|--purge' $files; then
	echo "check-scripts.sh: autoremove or purge in a package script" >&2
	bad=1
fi
exit $bad
