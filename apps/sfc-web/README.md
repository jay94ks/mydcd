# sfc-web

Seafield Cluster 웹 관리 UI를 서빙하고 화면 API(`/api/v1`)를 제공하는 데몬의 컨테이너 자료다. 이 이미지는 **cluster app image**이고, node.yaml `cluster_apps.web.enabled: true`로 켜면 sfcd가 **cluster app**(컨테이너 `sfc-cluster-app-web`)으로 띄운다(cluster apps). 웹 UI를 여는 ingress route(구현 순서 7단계)가 아직 없으므로, 아래 `docker run`은 그 전까지 개발용으로 남긴다. sfcd·sfcli CLI와 같은 Go 모듈의 별도 실행 파일 `cmd/sfc-web`으로 빌드하고, 독립 컨테이너로 돌며 호스트의 `sfcdp.sock`을 마운트받아 그 소켓으로만 sfcd와 이야기한다. 개발 흐름은 웹 개발 워크플로우, API는 [web-api](../../docs/reference/web-api.md), sfcd method 상태는 [CLUSTER_METHODS.md](CLUSTER_METHODS.md).

| 경로 | 내용 |
|---|---|
| `cmd/sfc-web` | 실행 파일(설정·어댑터 선택·HTTP 서버) |
| `internal/web/server` | 로그인 세션, `/api/v1`, 정적 파일 |
| `internal/web/store` | 웹 자체 데이터 bbolt(`web.db`) |
| `internal/web/sfc` | sfcd client 인터페이스와 어댑터 |
| `apps/sfc-web/web` | 프런트엔드(Vite + React + TS) |
| `apps/sfc-web/ui` | 프런트엔드 빌드를 실행 파일에 내장하는 패키지(`ui/dist`는 빌드 때 복사, git 제외) |

## 설정

플래그가 환경 변수보다 우선한다.

| 플래그 | 환경 변수 | 기본값 | 뜻 |
|---|---|---|---|
| `-listen` | `SFC_WEB_LISTEN` | `:8080` | HTTP 주소 |
| `-tls-cert`, `-tls-key` | `SFC_WEB_TLS_CERT`, `SFC_WEB_TLS_KEY` | 없음 | 직접 HTTPS로 받을 때 |
| `-socket` | `SFC_WEB_SOCKET` | `/run/sfc/sfcdp.sock` | sfcd가 이 클러스터 앱에 따로 여는 관리 소켓(호스트의 `state_dir/cluster-apps/web/run/`이 `/run/sfc`에 들어온다) |
| `-cluster` | `SFC_WEB_CLUSTER` |  | 소켓 뒤 sfcd의 클러스터 ID(hex 64자). 꼭 필요 |
| `-node` | `SFC_WEB_NODE` |  | 그 노드의 ID. 꼭 필요 |
| `-node-key` | `SFC_WEB_NODE_KEY` |  | 그 노드의 신원 키(hex 64자). CLI context처럼 설치 출력에서 받아 고정한다. 꼭 필요 |
| `-data-dir` | `SFC_WEB_DATA_DIR` | `/var/lib/sfc-web` | `web.db`(0600) 위치. 볼륨은 이 컨테이너만 마운트 |
| `-acme-listen` | `SFC_WEB_ACME_LISTEN` | 없음(끔) | ACME HTTP-01 응답 주소(평문 HTTP, 예 `:8081`). ingress가 `/.well-known/acme-challenge/`만 이리로 보낸다. 켜면 외부 도메인(DNS 공급자)에 없는 이름도 HTTP-01로 발급한다 |
| `-acme-advertise` | `SFC_WEB_ACME_ADVERTISE` | `-acme-listen`이 구체적인 IP:port면 그 값 | ingress가 응답기에 닿는 IP:port. 웹이 클러스터 응답기 설정에 채운다([web API](../../docs/reference/web-api/23-ui-57-59.md)) |
| `-direct-listen` | `SFC_WEB_DIRECT_LISTEN` | 없음(끔) | 어떤 프록시도 믿지 않는 평문 HTTP 주소(예 `:8082`). `X-Forwarded-*`·`Forwarded` 머리글을 버린다. sfcd가 node.yaml `port`를 여기로 이어 준다 |
| `-static-dir` | `SFC_WEB_STATIC_DIR` | 없음 | 내장 UI 대신 디스크에서 서빙(개발용) |
| `-trusted-proxies` | `SFC_WEB_TRUSTED_PROXIES` | 없음 | 이 컨테이너로 넘겨 주는 ingress의 IP·CIDR(쉼표로, sfc-system의 노드 TUN host 주소). 쿠키 Secure는 요청마다 정한다: 직접 받은 TLS이거나, 이 주소에서 온 연결이 `X-Forwarded-Proto: https`를 보낼 때 붙인다. 다른 연결의 그 헤더는 쓰지 않는다. 값이 없으면 보이지 않는 HTTPS 앞단이 있다고 보고 붙이되, loopback에서 직접 온 평문 연결(개발 실행)에서만 뺀다 |
| `-op-retention` | `SFC_WEB_OP_RETENTION` | `720h` | 확정된 작업 기록 보존 기간 |
| (환경 변수만) | `SFC_WEB_SEAL_KEY` | 없음 | 봉인 파일 키. 32바이트의 hex(64자) 또는 base64. 읽은 뒤 프로세스 환경에서 지운다. 명령줄 인자로는 받지 않는다 |
| `-seal-key-file` | `SFC_WEB_SEAL_KEY_FILE` | 없음 | 봉인 키를 담은 파일(Docker secret `/run/secrets/...`). `SFC_WEB_SEAL_KEY`와 함께 쓰지 않는다 |
| `-seal-key-next-file` | `SFC_WEB_SEAL_KEY_NEXT`, `SFC_WEB_SEAL_KEY_NEXT_FILE` | 없음 | 새 봉인 키. 시작할 때 모든 봉인 파일을 새 키로 다시 봉인한다. 끝나면 새 키를 `SFC_WEB_SEAL_KEY`로 옮긴다 |

bbolt는 파일 잠금으로 한 프로세스만 연다. 웹 컨테이너는 하나만 실행한다.

## 개발 실행

데몬은 실제 sfcd에만 붙는다. 가짜 어댑터(`sfc.NewFake`)는 server 시험 대역이라 실행 파일에 없다. 화면만 고칠 때는 프런트엔드 목업 모드(`npm run dev`, [web/README.md](web/README.md))를 쓴다.

```sh
# 개발 노드의 sfcd 소켓과 그 노드의 클러스터 ID·노드 ID·신원 키(설치 출력)로
go run ./cmd/sfc-web -socket /run/sfcdp.sock -cluster <hex> -node <노드> -node-key <hex> \
  -data-dir ./work/sfc-web
# 빌드된 UI를 디스크에서: 위에 -static-dir apps/sfc-web/web/dist
```

## 컨테이너

```sh
# 3rd-party submodule checkout·patch가 먼저 필요하다(3rd-party/README.md)
docker build -f apps/sfc-web/Dockerfile -t sfc-web .
docker run -d --name sfc-web \
  --user "$(stat -c %u /run/sfcdp.sock)" \
  -v /run/sfcdp.sock:/run/sfcdp.sock \
  -v sfc-web-data:/var/lib/sfc-web \
  -p 8080:8080 sfc-web
```

봉인 키는 처음 한 번 만들어(`openssl rand -hex 32`) 안전한 곳에 두고, Docker secret이나 읽기 전용 파일로 넘긴다(`-v /etc/sfc-web/seal.key:/run/secrets/seal-key:ro -e SFC_WEB_SEAL_KEY_FILE=/run/secrets/seal-key`). 키가 없으면 데몬은 뜨지만 AI·외부 DNS·인증서 자동화·알림은 꺼진다. 키를 잃으면 `secrets/`의 값은 되살릴 수 없으므로 각 키를 다시 입력해야 한다. 다른 키로 시작하면 `wrong-key`로 꺼지고 기존 파일은 건드리지 않는다.

공급자 진단 로그(외부 DNS·인증 기관 호출 기록)는 기본으로 꺼져 있다. 웹 앱 설정에서 켜면 임시 토큰이 나오고, `docker exec sfc-web sfc-web provider-log -tail 500 > provider-log.jsonl`처럼 같은 실행 파일의 `provider-log` 명령으로 읽는다. 1시간 동안 활동이 없으면 저절로 꺼진다([공급자 진단 로그](../../docs/reference/web-api/45-provider-log.md)).

소켓은 0600이므로 컨테이너 UID가 소켓 소유 UID와 같아야 한다. 이 UID는 관리 권한이 아니다. 웹 앱은 자기 관리 권한이 없고, 모든 조회·변경은 로그인한 사용자 자신의 SFCP 세션으로 실행된다. Docker 소켓은 마운트하지 않는다.

## cluster app image 묶음 만들기

sfcd가 cluster app으로 띄우려면 이미지를 OCI layout 묶음으로 서버의 `/usr/local/lib/sfc/images/sfc-web/`에 두고, sfcd가 믿는 릴리스 키로 서명한 릴리스 정보를 함께 넣는다(cluster apps 3.3절). 공식 릴리스 키가 아닌 키로 직접 빌드한 이미지를 돌릴 때는 그 공개키를 서버의 `/etc/sfc/release-keys/`에 둔다. sfcd를 다시 빌드할 필요는 없다.

공식 릴리스는 플랫폼마다 서명된 묶음 `sfc-web-image_<태그>_linux_<arch>.tar.gz`를 함께 올린다. 서버에서 `tar -xzf sfc-web-image_*.tar.gz -C /usr/local/lib/sfc/images/`로 풀면 `sfc-web/`이 되고, 공식 릴리스 키는 sfcd에 들어 있으므로 키 파일을 따로 두지 않는다.

```sh
# 키는 한 번만 만든다. lab.key(개인키)는 서버에 두지 않는다
go run ./tools/clusterapp-bundle keygen -out lab.key        # lab.pub도 생긴다
# 서버 플랫폼 하나로 OCI layout을 만든다(attestation manifest를 넣지 않는다)
docker buildx build -f apps/sfc-web/Dockerfile --platform linux/amd64 \
  --provenance=false --sbom=false -o type=oci,dest=sfc-web.tar .
mkdir -p dist/sfc-web && tar -xf sfc-web.tar -C dist/sfc-web
go run ./tools/clusterapp-bundle sign -key lab.key -app web -version 0.9.1-lab -bundle dist/sfc-web
# 서버에서(root)
install -d -m 0755 /etc/sfc/release-keys && install -m 0644 lab.pub /etc/sfc/release-keys/lab.pub
rm -rf /usr/local/lib/sfc/images/sfc-web && cp -a dist/sfc-web /usr/local/lib/sfc/images/sfc-web
```

sfcd는 맞추기 때마다 묶음을 다시 확인하므로, 새 묶음으로 바꾸면 새 digest의 이미지로 컨테이너를 다시 만든다. 서명이 맞지 않으면 서버 상세의 "기본 제공 앱"에 `release-unverified`가 보인다.

## 웹 데이터 되살리기

시스템 › 웹 앱 설정에서 올린 백업 파일은 `<data-dir>/web.db.restore`로 놓이고, 데몬을 **다시 시작할 때** `web.db`와 바뀐다. 바뀌기 전 파일은 `web.db.before-restore-<시각>`으로 옆에 남는다. 되살린 뒤 모든 웹 로그인은 끝난 것으로 처리되어 다시 로그인해야 한다.
