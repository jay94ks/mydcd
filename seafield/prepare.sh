#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# prepare.sh DIR: DIR에 Seafield 소스 트리를 만든다.
#   업스트림 태그 checkout → prune.txt 경로 삭제(커밋 1개) → series 순서로 git am.
# DIR이 이미 있으면 거부한다. 결과 트리의 HEAD는 마지막 패치 커밋이고,
# 업스트림 커밋에는 seafield-upstream, prune 커밋에는 seafield-pruned 태그가 붙는다.
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
dir=${1:?usage: prepare.sh DIR}
[ -e "$dir" ] && { echo "prepare.sh: $dir already exists" >&2; exit 2; }

repo=$(python3 -I -c 'import json,sys;print(json.load(open(sys.argv[1]))["repository"])' "$here/upstream.json")
tag=$(python3 -I -c 'import json,sys;print(json.load(open(sys.argv[1]))["tag"])' "$here/upstream.json")
commit=$(python3 -I -c 'import json,sys;print(json.load(open(sys.argv[1]))["commit"])' "$here/upstream.json")

git clone -q --depth 1 --branch "$tag" "$repo" "$dir"
got=$(git -C "$dir" rev-parse HEAD)
[ "$got" = "$commit" ] || { echo "prepare.sh: $tag is $got, upstream.json pins $commit" >&2; exit 3; }

g() { git -C "$dir" -c user.name=seafield -c user.email=seafield@invalid -c commit.gpgsign=false "$@"; }
g tag seafield-upstream

grep -vE '^\s*(#|$)' "$here/prune.txt" | while read -r path; do
	[ -e "$dir/$path" ] || { echo "prepare.sh: prune path missing upstream: $path" >&2; exit 4; }
	g rm -r -q -- "$path"
done
g commit -q --allow-empty -m "seafield: prune upstream paths (prune.txt)"
g tag seafield-pruned

grep -vE '^\s*(#|$)' "$here/series" | while read -r patch; do
	g am -q --keep-cr "$here/patches/$patch" || { echo "prepare.sh: $patch does not apply" >&2; g am --abort || true; exit 5; }
done
echo "prepare.sh: $dir ready ($(git -C "$dir" rev-list --count seafield-pruned..HEAD) patches on $tag)"
