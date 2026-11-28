#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# test-in-container.sh deb|rpm|tar: one install test run by test.sh inside a
# clean container. /dist holds the packages; OLD, NEW, ARCH, RARCH come from
# the environment.
set -euo pipefail
kind=$1
fail() { echo "FAIL: $*" >&2; exit 1; }

packages() {
	case $kind in
	deb) dpkg-query -W -f '${Package} ${Version}\n' | grep -vE '^(sfcli|sfcd|sfc-web-image) ' | LC_ALL=C sort ;;
	rpm) rpm -qa --qf '%{NAME} %{VERSION}-%{RELEASE}\n' | grep -vE '^(sfcli|sfcd|sfc-web-image) ' | LC_ALL=C sort ;;
	tar) dpkg-query -W -f '${Package} ${Version}\n' | LC_ALL=C sort ;;
	esac
}

# Operator state that no package step may delete.
mkdir -p /etc/sfc /var/lib/sfc/state /etc/sfe /var/lib/sfe
echo 'version: 1' >/etc/sfc/node.yaml
echo keep >/var/lib/sfc/state/marker
echo keep >/var/lib/sfe/marker
before=$(packages)

if [ "$kind" = tar ]; then
	prefix=/usr/local
	tar -C /usr/local --strip-components=1 -xzf "/dist/sfc_v${OLD}_linux_${ARCH}.tar.gz"
	units=/usr/local/share/sfc/systemd
else
	prefix=/usr
	units=/usr/lib/systemd/system
fi

install_version() { # install_version VERSION
	local v=$1
	case $kind in
	deb) dpkg -i "/dist/sfcli_${v}_${ARCH}.deb" "/dist/sfcd_${v}_${ARCH}.deb" "/dist/sfc-web-image_${v}_${ARCH}.deb" >/tmp/out 2>&1 || { cat /tmp/out; fail "dpkg -i $v"; } ;;
	rpm) rpm -Uvh "/dist/sfcli-${v}-1.${RARCH}.rpm" "/dist/sfcd-${v}-1.${RARCH}.rpm" "/dist/sfc-web-image-${v}-1.noarch.rpm" >/tmp/out 2>&1 || { cat /tmp/out; fail "rpm -U $v"; } ;;
	esac
}

check_files() {
	local lib=$prefix/lib/sfc
	for b in sfcd sfed sfe-runc containerd containerd-shim-runc-v2 runc; do
		[ -x "$lib/bin/$b" ] && [ ! -L "$lib/bin/$b" ] || fail "$lib/bin/$b missing or a link"
	done
	[ "$(readlink -f "$prefix/bin/sfcd")" = "$lib/bin/sfcd" ] || fail "$prefix/bin/sfcd does not lead to $lib/bin/sfcd"
	[ -x "$prefix/bin/sfcli" ] || fail "$prefix/bin/sfcli"
	local help
	help=$("$prefix/bin/sfcli" --help 2>&1) || true
	grep -qF "read $prefix/share/sfc/SKILL.md" <<<"$help" || fail "sfcli --help does not find $prefix/share/sfc/SKILL.md"
	"$lib/bin/runc" --version >/dev/null || fail "runc does not run"
	"$lib/bin/containerd" --version >/dev/null || fail "containerd does not run"
	"$lib/bin/sfed" --version >/dev/null || fail "sfed does not run"
	[ -f "$lib/images/sfc-web/sfc-release.sig" ] || fail "sfc-web bundle missing"
	for u in sfcd sfed; do
		[ -f "$units/$u.service" ] || fail "$units/$u.service missing"
		grep -q "$lib/bin/" "$units/$u.service" || fail "$u.service does not point at $lib/bin"
		! grep -q '@LIBDIR@' "$units/$u.service" || fail "$u.service still has @LIBDIR@"
	done
	grep -q "^Environment=PATH=$lib/bin:" "$units/sfed.service" || fail "sfed.service PATH"
	# Minimal Ubuntu images tell dpkg to skip /usr/share/doc.
	if ! grep -qsE 'path-exclude[= ]/usr/share/doc' /etc/dpkg/dpkg.cfg.d/*; then
		grep -q '^containerd ' "$prefix/share/doc/sfcd/THIRD_PARTY_NOTICES" || fail "engine notices"
	fi
	[ "$(stat -c %U "$lib/bin/sfcd")" = root ] || fail "owner"
}

kept() {
	[ -f /etc/sfc/node.yaml ] && [ -f /var/lib/sfc/state/marker ] && [ -f /var/lib/sfe/marker ] && [ -d /etc/sfe ] || fail "operator state deleted ($1)"
}

if [ "$kind" = tar ]; then
	check_files
	kept install
	[ "$(packages)" = "$before" ] || fail "package list changed"
	echo "PASS tar"
	exit 0
fi

install_version "$OLD"
grep -q "sfcd is installed but not enabled" /tmp/out || fail "no next-steps message on first install"
check_files
kept install
case $kind in
deb) [ "$(dpkg-query -W -f '${Version}' sfcd)" = "$OLD" ] || fail version ;;
rpm) [ "$(rpm -q --qf '%{VERSION}' sfcd)" = "$OLD" ] || fail version ;;
esac

install_version "$NEW"
! grep -q "sfcd is installed but not enabled" /tmp/out || fail "first-install message on upgrade"
check_files
kept upgrade
case $kind in
deb) [ "$(dpkg-query -W -f '${Version}' sfcd)" = "$NEW" ] || fail "upgrade version" ;;
rpm) [ "$(rpm -q --qf '%{VERSION}' sfcd)" = "$NEW" ] || fail "upgrade version" ;;
esac

case $kind in
deb)
	dpkg -r sfc-web-image sfcd sfcli >/tmp/out 2>&1 || { cat /tmp/out; fail "dpkg -r"; }
	[ ! -e /usr/lib/sfc/bin/sfcd ] && [ ! -e /usr/bin/sfcli ] || fail "files left after remove"
	kept remove
	dpkg -P sfc-web-image sfcd sfcli >/tmp/out 2>&1 || { cat /tmp/out; fail "dpkg -P"; }
	grep -q "kept /etc/sfc, /var/lib/sfc" /tmp/out || fail "no kept-state message on purge"
	kept purge
	[ -z "$(dpkg-query -W -f '${Package}\n' 'sfc*' 2>/dev/null | grep -E '^(sfcli|sfcd|sfc-web-image)$' || true)" ] || fail "still known to dpkg"
	;;
rpm)
	rpm -e sfc-web-image sfcd sfcli >/tmp/out 2>&1 || { cat /tmp/out; fail "rpm -e"; }
	[ ! -e /usr/lib/sfc/bin/sfcd ] && [ ! -e /usr/bin/sfcli ] || fail "files left after erase"
	grep -q "kept /etc/sfc, /var/lib/sfc" /tmp/out || fail "no kept-state message on erase"
	kept erase
	;;
esac
[ "$(packages)" = "$before" ] || { diff <(echo "$before") <(packages) || true; fail "another package was installed or removed"; }
echo "PASS $kind"
