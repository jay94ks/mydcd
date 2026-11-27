# Seafield

Seafield는 sfc 노드에서 Docker Engine 대신 도는 컨테이너 엔진이다. Moby(dockerd)를 업스트림으로 두고, sfcd와 함께 노드 데몬 패키지에 들어가는 독립 데몬이다. 방향과 근거는 Seafield 검토에 있다.

저장소에는 포크 이력을 두지 않는다. **업스트림 태그 하나 + 지울 경로 목록 + 패치 목록**만 둔다.

| 파일 | 내용 |
|---|---|
| [upstream.json](upstream.json) | 업스트림 저장소·태그·커밋, 빌드 Go 버전 |
| [prune.txt](prune.txt) | 통째로 지우는 업스트림 경로. 삭제 diff 대신 경로 목록으로 지워 업스트림 변경에 덜 깨진다 |
| [series](series) | 패치 적용 순서 |
| [patches/](patches) | `git format-patch` 형식 패치. 커밋 하나가 패치 하나 |
| [prepare.sh](prepare.sh) | `DIR`에 업스트림을 받고 prune → 패치 적용 |
| [build.sh](build.sh) | `DIR`에서 `seafield` 바이너리 빌드 |
| [refresh-patches.sh](refresh-patches.sh) | `DIR`의 커밋을 `patches/`·`series`로 다시 씀 |
| [docs/](docs) | 업스트림과 다른 점만 적은 문서 |
| [packaging/](packaging) | sfed.service, daemon.json 견본 |

## 작업 순서

```sh
./seafield/prepare.sh /tmp/sf          # 업스트림 + prune + 패치
# /tmp/sf에서 고치고 커밋한다 (커밋 하나 = 패치 하나, 제목이 패치 이름)
./seafield/refresh-patches.sh /tmp/sf  # patches/, series 갱신
./seafield/build.sh /tmp/sf /tmp/seafield 0.0.0-dev
```

- `prepare.sh`는 업스트림 커밋에 `seafield-upstream`, prune 커밋에 `seafield-pruned` 태그를 붙인다. 패치는 그 위에 쌓인다.
- 업스트림 태그를 올릴 때는 `upstream.json`만 바꾸고 `prepare.sh`를 돌린다. 적용이 깨지는 패치 번호가 손볼 곳이다. prune 경로가 업스트림에서 사라졌으면 `prepare.sh`가 알려 준다.

## 패치 규칙

- 업스트림 파일은 **연결부만 작게** 고친다(등록·시작 코드에서 지운 패키지 부르기 빼기 등). 업스트림 dockerd 설정이나 빌드 태그로 되는 것은 패치하지 않는다.
- Seafield 추가 기능은 새 파일·새 디렉터리로 넣고 `SPDX-License-Identifier: Apache-2.0`을 단다. 업스트림 파일의 LICENSE·NOTICE·저작권 표시는 그대로 둔다(Apache-2.0 4조). 고친 업스트림 파일은 패치 자체가 변경 기록이다.
- 제품 이름에 "Docker"·"Moby"를 쓰지 않는다. Engine API 호환이라는 사실 설명만 한다.
- vendor와 go.mod는 건드리지 않는다(지운 패키지의 의존은 링크되지 않으므로 남겨도 된다). 의존을 바꿔야 할 때만 별도 패치로 한다.

## 문서

엔진 자체(Engine API, dockerd 설정, 동작)는 다시 설명하지 않는다. 고정한 업스트림 버전의 문서를 본다.

- Engine API: <https://docs.docker.com/reference/api/engine/> (Seafield가 보고하는 API 버전 기준)
- dockerd 설정과 옵션: <https://docs.docker.com/reference/cli/dockerd/>
- 업스트림 소스와 문서: <https://github.com/moby/moby/tree/docker-v29.10.1>

Seafield 문서는 업스트림과 다른 점만 적는다.

- [바꾼 것·지운 것](docs/changes.md)
- [더한 것](docs/additions.md)
- [Seafield → sfcd 소켓 (설계)](docs/sfcd-socket.md)
