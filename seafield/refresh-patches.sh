#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# refresh-patches.sh DIR: DIR(prepare.sh 결과 + 그 위에 새 커밋)의
# seafield-pruned..HEAD 커밋을 patches/와 series로 다시 쓴다.
# 커밋 하나가 패치 하나다. 커밋 제목이 패치 이름이 된다.
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
dir=${1:?usage: refresh-patches.sh DIR}
[ -z "$(git -C "$dir" status --porcelain --untracked-files=no)" ] || { echo "refresh-patches.sh: $dir has uncommitted changes" >&2; exit 2; }
rm -f "$here"/patches/*.patch
git -C "$dir" format-patch -q --zero-commit --no-signature --no-stat -o "$here/patches" seafield-pruned..HEAD
{
	echo "# 적용 순서. prune.txt를 지운 뒤 위에서부터 git am 한다. refresh-patches.sh가 쓴다."
	(cd "$here/patches" && ls -1 *.patch)
} > "$here/series"
echo "refresh-patches.sh: $(grep -vc '^#' "$here/series") patches"
