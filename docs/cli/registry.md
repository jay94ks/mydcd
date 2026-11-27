# sfcli registry: 내장 registry와 외부 이미지 출처

작업 공간(tenant)의 내장 registry를 만들고 켜고 끄며, 앱이 이미지를 받아 올 외부 registry(외부 출처)를 등록한다. 이미지 자체는 [`sfcli image`](image.md), 빌드는 [`sfcli build`](build.md)가 다룬다.

## 내장 registry

| 명령 | 하는 일 |
|---|---|
| `sfcli registry list` | registry 목록과 상태(serving·stopped 등) |
| `sfcli registry show NAME` | 한 registry의 설정, 상태, 쓰는 공간 |
| `sfcli registry create NAME --volume VOL --authority HOST[:PORT] [--node NODE] [--address IP:PORT] [--max-size 50GiB]` | 고정 Volume 위에 registry를 만들고 바로 켠다. 기본 서버는 Volume의 서버, 기본 크기는 Volume 크기 |
| `sfcli registry start NAME` · `stop NAME` | 켜거나 끄고, 끝날 때까지(serving·stopped) 기다린다. 이미지는 그대로 남는다 |
| `sfcli registry delete NAME` | 꺼진 registry를 지운다. Volume과 그 안의 데이터는 남는다 |
| `sfcli registry gc NAME` | 어떤 이미지도 쓰지 않는 layer의 공간을 비운다 |
| `sfcli registry prune NAME [--older-than 720h] [--keep N] [--untagged] [--repository R] [--exclude-tag T] [--protect DIGEST] [--external] [--gc] [--dry-run]` | 조건에 맞는 오래된 이미지를 보여 주고, 물어본 뒤 지운다. 앱이 쓰는 이미지는 남긴다 |
| `sfcli registry login NAME --repository R [--push] \| --catalog` | `docker login`에 넣을 짧은 수명의 비밀번호를 표준 출력에 쓴다 |
| `sfcli registry export NAME --out FILE [--repository R ...] [--tag T ...]` | registry의 태그 붙은 이미지(또는 고른 저장소·태그)를 OCI image layout tar 하나로 저장한다 |
| `sfcli registry import NAME --file FILE [--repository R] [--dry-run]` | tar의 이미지를 같은 저장소·태그·digest로 registry에 올린다 |

- TLS 인증서는 클러스터 [인증서 보관함](../reference/certificate-store.md)에서 `--authority`의 호스트로 찾는다. 그 호스트가 등록된 도메인(`sfcli domain`, IP authority면 그 IP 항목) 안에 있고 연결된 인증서가 있어야 registry가 켜진다. 인증서를 새로 올리면 켜진 registry가 다음 확인 때 새 연결부터 바꿔 쓰고, 호스트에 인증서가 없어지면(도메인 제거, `certificate disable`) registry를 멈춘다. `registry show`의 인증서 ID는 서버가 지금 쓴다고 보고한 인증서다.
- registry는 요청을 64개까지 함께 받으므로, 그 서버의 한도(`sfcli node quota set --consumers`)와 작업 공간의 그 서버 몫(`sfcli tenant quota set --consumers`)이 모두 64 이상이어야 켜진다. 모자라면 `registry create`가 어느 한도인지와 고치는 명령을 말하고 거절한다. 이미 만든 registry가 `starting`에 머물면 `registry show`의 `waiting`이 같은 이유를 보여 준다.
- 빌드가 이미지를 올리는 서버는 `--authority`의 이름을 DNS로 찾을 수 있어야 한다.

`start`·`stop`·`gc`·`prune`은 서버가 받은 뒤에도 일이 이어진다. 기본은 끝날 때까지 진행을 stderr에 보여 주며 기다린다. `--no-wait`는 서버가 받으면 바로 돌아오고, 나중에 `sfcli op show ID`로 확인한다. 기다리다 Ctrl-C를 누르면 기다리기만 멈추고 서버의 일은 계속된다.

```sh
sfcli registry create shop-registry --volume registry-data --authority registry.shop.test:5443
sfcli registry login shop-registry --repository shop/web --push | \
  docker login registry.shop.test:5443 --username "$(sfcli whoami)" --password-stdin
sfcli registry prune shop-registry --older-than 720h --keep 5 --dry-run
```

### 이미지 내보내기·가져오기

registry는 서버와 함께 잃을 수 있는 고정 Volume 위에 있으므로, 이미지는 `export`로 이 컴퓨터에 받아 둔다. 파일은 표준 OCI image layout(`oci-layout`, `index.json`, `blobs/sha256/…`)을 묶은 tar라서 `skopeo`(`oci-archive:`)나 `crane`으로도 읽고 쓸 수 있다. 이미지 내용만 담고 비밀값이 없으므로 암호화하지 않는다. 각 이미지 항목에는 태그(`org.opencontainers.image.ref.name`)와 저장소(`io.sfc.repository`)가 붙는다.

- 이미지는 이 컴퓨터와 registry 주소(`--authority`) 사이를 바로 오간다. sfcd가 저장소마다 짧은 수명의 자격(export는 pull, import는 pull·push)을 주고, 전송이 길면 만료 전에 새로 받는다. 이 컴퓨터가 `--authority`의 이름을 찾고 그 인증서를 믿을 수 있어야 한다.
- `export`는 시작할 때 태그→digest 목록을 고정하고 digest로 읽는다. 그 사이 push가 있어도 파일은 시작 시점과 같다. 그 사이 지워진 이미지가 있으면 빠뜨리지 않고 실패한다. 파일은 `FILE` 옆에 임시로 쓰고 다 쓴 뒤 이름을 바꾸며, 이미 있는 `FILE`은 덮어쓰지 않는다. 끊기면 같은 명령을 다시 돌린다. 태그 없는 이미지는 담지 않는다.
- `import`는 먼저 계획을 보여 준다. 태그마다 `add`(새로), `same`(이미 같은 digest), `move`(다른 digest를 가리키던 태그)이고, `move`는 그 태그를 쓰는 앱을 함께 보여 준 뒤 확인을 받는다(`-y`로 건너뜀). 앱은 다음 배포·재시작 때 새 이미지를 쓴다. registry에 이미 있는 blob은 보내지 않으므로, 끊기면 같은 import를 다시 돌려 이어 간다. 파일이 registry 크기 한도(`--max-size`)나 blob 수 한도보다 크면 보내기 전에 거절한다. 그보다 작아도 registry가 지금 가진 이미지와 합쳐 넘치면 registry가 중간에 거절한다.
- 다른 도구가 만든 파일처럼 저장소가 적혀 있지 않은 이미지는 `--repository`로 저장소를 준다.

```sh
sfcli registry export shop-registry --out shop-images.tar
sfcli registry import shop-registry --file shop-images.tar --dry-run
```

권한은 그 registry의 pull(export)과 push(import) 권한이다(`registry login`과 같다).

`login`은 비밀번호를 터미널에 그대로 찍지 않는다. 파이프나 파일로만 받는다. 사용자 이름은 로그인한 사용자다. `--push`에는 registry 관리 권한이 필요하다.

## 외부 출처

| 명령 | 하는 일 |
|---|---|
| `sfcli registry external list` · `show NAME` | 외부 출처 목록과 설정(자격 증명은 Vault 키 이름만 보인다) |
| `sfcli registry external add NAME --authority HOST [--repository PATH\|prefix/**\|**] [--auth none\|password\|token] [--secret [REALM/]ID] [--username-key K] [--password-key K] [--ca [REALM/]ID] [--ca-key K] [--disabled]` | 출처를 더하거나 같은 이름의 설정을 바꾼다. authority와 repository는 바꿀 수 없다 |
| `sfcli registry external bind NAME --node NODE [--group-password-fd REALM/GROUP=FD ...]` | 그 서버에서 이 출처로 받아 오는 reader를 켠다. 출처 하나에 reader는 하나라서, 다른 서버로 옮기려면 먼저 `unbind`한다. 보호된 Vault 비밀을 쓰면 Group 비밀번호를 터미널에서 묻고, 스크립트는 `--group-password-fd`로 열린 파일 서술자에서 읽게 한다(클러스터 영역은 `/GROUP`) |
| `sfcli registry external unbind NAME` | reader를 끈다 |
| `sfcli registry external remove NAME` | 출처를 지운다 |
| `sfcli registry external check NAME [--image IMAGE]` | bind된 reader 서버에서 로그인해 보고, `--image`가 있으면 그 이미지도 읽어 본다. 실패하면 결과 코드(예: `PLAIN_HTTP`, `INVALID_CA`, `UNAUTHORIZED`, 이미지 config의 os·architecture가 reader 서버와 다르거나 비어 있으면 `PLATFORM_MISMATCH`)와 설명을 보이고 종료 코드 3 |
| `sfcli registry external pulls` | 앱 배포가 외부 출처로 이미지를 받은 최근 결과(출처, 단계, 결과 코드). `check`는 여기에 남지 않는다 |

자격 증명 값은 명령줄에 쓰지 않는다. [`sfcli secret`](secret.md)으로 Vault에 넣고 `--secret`·`--ca`로 그 이름과 키만 가리킨다. `ID`만 쓰면 작업 공간 자신의 Vault, `/ID`는 클러스터 Vault, `REALM/ID`는 그 영역이다. `add`는 그 비밀과 키가 실제로 있는지 먼저 확인한다.

외부 출처는 HTTPS로만 읽는다. 평문 HTTP registry는 `PLAIN_HTTP`로 거절되며, Docker의 insecure-registries 설정과 상관없다. 사설 CA로 서명한 인증서는 `--ca`로 CA 인증서를 준다.

## 종료 코드

0 성공, 1 실패, 2 잘못된 명령줄, 3 `external check` 실패, 4 결과를 아직 모름(`sfcli op show ID`로 확인).
