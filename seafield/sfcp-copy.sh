#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
#
# Copy pkg/sfcp/wire and pkg/sfcp/enginemux (pkg/sfcp before the rename)
# from the cluster source tree into the engine work tree
# (daemon/seafield/sfcp), or check that the engine copy is identical.
#
#   ./seafield/sfcp-copy.sh copy  SRC DIR   # SRC = cluster repo root, DIR = engine work tree
#   ./seafield/sfcp-copy.sh check SRC DIR   # exit 1 when the copy differs
#
# The only allowed difference is the import path of the wire package.
set -eu
mode=$1 src=$2 dir=$3
pkgs="wire enginemux"
dst=$dir/daemon/seafield/sfcp
base=$src/pkg/sfcp
[ -d "$base" ] || base=$src/pkg/sfcp
rewrite() {
	sed -E 's#"github\.com/jay94ks/[A-Za-z0-9_.-]+/pkg/(sfcp|sfcp)/#"github.com/moby/moby/v2/daemon/seafield/sfcp/#' "$1"
}
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
for p in $pkgs; do
	[ -d "$base/$p" ] || { echo "missing $base/$p" >&2; exit 2; }
	mkdir -p "$tmp/$p"
	for f in "$base/$p"/*.go; do
		rewrite "$f" >"$tmp/$p/$(basename "$f")"
	done
done
case $mode in
copy)
	rm -rf "$dst"
	mkdir -p "$dst"
	cp -r "$tmp"/* "$dst"/
	echo "copied $pkgs into $dst"
	;;
check)
	if diff -r "$tmp" "$dst" >&2; then
		echo "engine copy of pkg/sfcp matches"
	else
		echo "engine copy of pkg/sfcp differs; run: $0 copy $src $dir" >&2
		exit 1
	fi
	;;
*) echo "usage: $0 copy|check SRC DIR" >&2; exit 2 ;;
esac
