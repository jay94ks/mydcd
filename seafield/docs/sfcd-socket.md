# Seafield → sfcd 소켓 (설계, 일부 구현)

Seafield가 판단이 필요한 일을 sfcd에게 바로 묻는 경로다. 엔진 API(sfcd → Seafield)의 반대 방향이다. 내장 볼륨 드라이버, 내장 네트워크 드라이버, 이미지 원천이 이 소켓을 쓴다.

## 연결 (SFCP로 바뀜, Jay 2026-11-27 17:51 KST)

엔진(`sfed`)과 노드 데몬(`sfcd`)은 엔진 전용 소켓 하나에서 **SFCP로만** 이야기한다. 엔진 쪽은 패치 0015로 옮겼다. 아래 볼륨·네트워크 절의 HTTP 경로는 처음 설계로 뜻만 남긴 것이고, 실제 요청·답은 "op 구조체" 표가 정한다.

| 소켓 | 연 쪽 | 쓰임 |
|---|---|---|
| `/run/sfcdp.sock` | sfcd | CLI·웹 관리 소켓(SFCP). 엔진 purpose는 열지 않는다 |
| `/run/sfe/sfcd.sock` | sfcd | **엔진 전용 SFCP.** root `0600`, 로컬 엔진 모드(TLS·로그인 없이 커널 상대 확인만) |
| `/run/sfe/sfed.sock` | sfed | 업스트림 Engine API(HTTP)만 |

- sfed가 `/run/sfe/sfcd.sock`에 붙고, 그 세션 하나로 양쪽 호출이 다 오간다.
- 상대 확인: sfcd는 받을 때 `SO_PEERCRED` uid 0 + `SO_PEERPIDFD` 실행 파일이 sfed인지, sfed는 붙은 뒤 상대가 sfcd인지 본다. 허용 경로는 `/usr/lib/sfc/bin/`, `/usr/local/lib/sfc/bin/`, `/usr/local/bin/` 아래의 그 이름.
- fd(볼륨 mount 답)는 프레임 머리 byte 8의 fd 수(0–4)와 그 프레임의 `sendmsg`에 붙인 `SCM_RIGHTS`로 싣는다. 로컬 엔진 모드에서만 허용.

엔진 전용 purpose 구역 32–47(SFCP 구조 정리 스레드와 합의). 연산은 kind가 아니라 본문의 op 이름으로 나눈다. kind는 SFCP 공통 규칙(1 요청, 2 응답, 4 조각, 16+ purpose 전용).

| purpose | 제공 | 내용 |
|---|---|---|
| 32 EngineEvents | sfed | 구독 1번 → 사건 묶음을 생길 때마다 push. gap·boot는 본문 필드 |
| 33 EngineLog | sfed | 로그 queue bulk(조각) |
| 34 EngineLogAck | sfed | 가져간 범위 확인 → 엔진이 지움 |
| 35 EngineVolume | sfcd | create/get/list/mount(+fd)/unmount/remove |
| 36 EngineNetwork | sfcd | create/created/join/leave/delete |
| 37 EngineImage | sfcd | manifest, blob(offset부터 조각). 다른 서버에 있으면 sfcd가 mesh에서 ImageContent로 가져온다 |
| 38 EngineExec | sfed | exec의 프로세스 묶음 전체 끝내기(cgroup.kill). [더한 것](additions.md#exec-프로세스-묶음-감독) |

### 프레임과 본문 (SFCP 스레드와 확정, 2026-11-27)

- 다중화: 세션 하나 위에 스트림(`pkg/sfcp/enginemux`). listener(sfcd)가 여는 스트림은 홀수, dialer(sfed)가 여는 스트림은 짝수 ID. 스트림 끝은 kind가 아니라 머리 byte 9의 bit0 FIN, bit1 RST. 요청자가 취소하면 RST.
- 흐름 제어: 스트림마다 256KiB 창, 읽은 만큼 purpose 47 EngineMux kind 1로 돌려준다. kind 7/8 ACK는 "저장했다" 같은 뜻이 필요할 때만.
- 본문: Management·User와 같은 관례. field 1에 엄격한 JSON(`schema.Decode`: 모르는 key·중복 key 거절).

| kind | field 1 JSON |
|---|---|
| 1 요청 | `{"Schema":1,"Op":"…","OpID":"…","BootID":"…", …op별 값}` |
| 2 응답 | `{"Schema":1,"OpID":"…","Result":"applied"\|"not-applied"\|"unknown","Reason":"…", …op별 값}` |
| 4 조각 | `sfcp.WriteChunk` 형식(로그 bulk, blob) |

- `OpID`는 재시도에도 같은 값, `BootID`는 보낸 쪽 기동마다 바뀌는 값.
- `Reason`(not-applied일 때): `invalid`, `not-found`, `conflict`, `not-owner`, `not-ready`, `refused`. 보내기 전에 실패하면 not-applied, 보낸 뒤 실패하면 unknown(`CallError.Sent`).
- fd: 머리 byte 8의 수(0–4)만큼 같은 프레임에 붙고, JSON에는 순번(`"Fds":[0]`)으로 가리킨다.
- 한도: 요청 64KiB, 응답 128KiB(조각은 별도).
- 중첩 값(경로, dev/ino, routes 등)은 JSON 객체로 둔다. 각 op의 값은 아래 볼륨·네트워크·이미지 절의 표 그대로다.

### op 구조체 (엔진 패치 0015에 구현)

sfcd는 요청을 엄격하게 읽고 `json.Marshal` 결과와 같아야 받는다(`schema.Decode`). 그래서 양쪽 Go 구조체가 필드 순서·타입·태그까지 같아야 한다. json 태그 없음(필드 이름이 key), omitempty 없음. map·slice는 nil 대신 `{}`·`[]`. 요청은 `Request{Schema, Op, OpID, BootID}`, 답은 `Reply{Schema, OpID, Result, Reason(omitempty), Fds(omitempty)}`를 맨 앞에 embed한다. 거절 답도 그 op의 답 구조체 전체(op 값은 0)다.

엔진이 부르는 것(sfcd가 답함):

| purpose | op | 요청 필드(Request 뒤) | 답 필드(Reply 뒤) | OpID |
|---|---|---|---|---|
| 35 | `mount` | `Name, MountID, ContainerID string` | `ReadOnly bool; Dev, Ino uint64` + fd 1개 | `mount:<mount_id>` |
| 35 | `unmount` | `Name, MountID string` | 없음 | `unmount:<mount_id>` |
| 35 | `create` | `Name string; Opts map[string]string` | `Name string` | `create:<name>` |
| 35 | `get` | `Name string` | `Name, Status string` | 무작위 |
| 35 | `list` | 없음 | `Volumes []string` (정렬) | 무작위 |
| 35 | `remove` | `Name string` | 없음(sfcd가 거절) | 무작위 |
| 36 | `create` | `NetworkID, Name string; Labels, Options map[string]string; IPAM []struct{Subnet, Gateway string}` | `Bridge string; MTU int` | `create:<nid>` |
| 36 | `created` | `NetworkID, Name string; Labels map[string]string; Bridge string; MTU int; Gateway []string` | 없음 | `created:<nid>` |
| 36 | `delete` | `NetworkID, Name string; Labels map[string]string` | 없음 | `delete:<nid>` |
| 36 | `join` | `NetworkID, Endpoint, ContainerID, ContainerName string; ContainerLabels map[string]string; Addresses []string; MAC, SandboxKey, HostVeth string` | `Allow bool; MTU int; Routes []struct{Destination, NextHop string}; Sysctls map[string]string` | `join:<eid>` |
| 36 | `leave` | `NetworkID, Endpoint, ContainerID string; Addresses []string` | 없음 | `leave:<eid>` |
| 37 | `manifest`, `blob` | `Repository, Digest string; Offset uint64` | `ContentType string; Size int64` + kind 4 조각 | 읽기만 한다(같은 요청을 다시 보내도 된다) |

sfcd가 부르는 것(엔진이 답함):

| purpose | op | 요청 필드 | 답 필드 |
|---|---|---|---|
| 32 | `subscribe` | `After uint64` | `Boot string; Last uint64`, 그 뒤 kind 16 `{Boot string; Gap *{From, To uint64}; Records []Record}` (Record는 `seq`·`boot`·`event` 태그의 업스트림 인코딩) |
| 33 | `bulk` | `Container string; After uint64; MaxBytes int` | `Count int; First, Last uint64; Gap *{From, To uint64}; Live bool; Size int` + kind 4 조각, FIN |
| 34 | `ack` | `Container string; Upto uint64` | 없음 |
| 38 | `kill` | `ExecID string` | `Tree string` (`ended`) |

- 상대가 없거나 답하지 않으면 그 요청을 쓰는 동작(볼륨 마운트, 네트워크 참여, 이미지 받기)은 실패로 끝난다. 엔진이 대신 판단하지 않는다.
- 맡은 곳: 공개 wire 패키지(`pkg/sfcp/wire`), 로컬 엔진 모드, fd 싣기, purpose 표는 SFCP 스레드. sfed 쪽 코드와 각 purpose 처리, 엔진 사본이 같은지 보는 스크립트는 이 PR.

## 볼륨 (드라이버 이름 `sfc`)

엔진의 볼륨 드라이버 호출을 그대로 sfcd에 넘긴다. 저장 경로·용량·소유·공유(VolumeFS) 판단과 실제 디렉터리 준비는 sfcd가 하고, 엔진은 돌려받은 경로를 컨테이너에 bind한다.

| 엔진 호출 | 요청 | 답 |
|---|---|---|
| `Create(name, opts)` | `POST /v1/volumes/create {name, opts}` | `{name, created_at}`. sfcd가 미리 만든 볼륨만 받는다(엔진 API로 새 볼륨을 만들 수 없음) |
| `Get(name)`, `List()` | `GET /v1/volumes/{name}`, `GET /v1/volumes` | `{name, created_at, status}` |
| `Mount(id)` | `POST /v1/volumes/{name}/mount {mount_id, container_id}` | `{read_only, dev, ino}` + 디렉터리 fd (아래) |
| `Unmount(id)` | `POST /v1/volumes/{name}/unmount {mount_id}` | 204 |
| `Remove` | `DELETE /v1/volumes/{name}` | sfcd가 지금 지워도 된다고 할 때만 204 |

### Mount 답: 디렉터리 fd (볼륨 스레드와 합의, 2026-11-27)

`Mount` 답은 경로가 아니라 sfcd가 연 디렉터리 fd다. 엔진이 경로를 다시 해석하지 않으므로 지금 Docker 앞에서 하는 bind 원천 확인(`internal/engine/bind_peer_linux.go`)이 엔진 경로에서는 필요 없다.

- 답: 본문 `{read_only, dev, ino}` + 같은 연결의 `SCM_RIGHTS` fd 1개(`O_RDONLY|O_DIRECTORY|O_CLOEXEC`).
- 엔진: 받은 fd로 `open_tree(fd, "", OPEN_TREE_CLONE|AT_EMPTY_PATH)` → 엔진 전용 경로(`/run/sfe/volumes/<mount_id>`)에 `move_mount` → 그 경로를 runc에 준다. `read_only`면 `mount_setattr`로 읽기 전용을 건다. `/proc/self/fd/N`을 runc에 주지 않는다(다른 프로세스에서는 다른 fd). fd는 컨테이너가 시작된 뒤 닫는다.
- sfcd는 Mount 때 A3 pin을 새로 빌리지 않는다. 컨테이너를 만들기 전에 빌린 pin이 그 `container_id`의 consumer로 journal에 있는지만 보고, 디렉터리를 새로 열어 같은 데이터인지 확인한 뒤 fd를 준다. `Unmount`는 pin을 돌려주지 않는다(pin은 지금처럼 컨테이너가 끝난 뒤 반납).
- 거절: sfcd가 만들지 않은 컨테이너(`docker run -v`로 직접 붙인 것)는 `not-owner`, 이동·복원 중이거나 적용 전이면 `not-ready`. 둘 다 엔진은 컨테이너 시작을 실패시킨다. 빈 디렉터리를 만들거나 로컬 볼륨으로 넘어가지 않는다.
- 제약: sfcd와 엔진은 같은 마운트 네임스페이스에 있어야 한다(`open_tree` clone 조건). 공유 볼륨(FUSE)도 같은 방식이고, 컨테이너 접근에는 `allow_other`가 필요하다.
- sfcd는 시작 뒤 실제 프로세스 마운트를 보는 확인(`CheckProcessBindSources`)을 당분간 유지한다.
- 오류 본문은 `{code, message}`. `code`는 `not-ready` 또는 `not-owner`.
- sfcd 쪽 답은 볼륨 스레드가 `engineops` 표(PR #673)에 등록한다(PR #694). 엔진 쪽은 패치 0009·0015로 됨.

`mount_id`는 엔진이 마운트마다 주는 값이다. 같은 `mount_id`로 다시 오면 같은 답을 준다(원 작업 규칙).

## 네트워크 (드라이버 이름 `sfc`)

veth·bridge·IPAM은 업스트림 libnetwork bridge 드라이버를 그대로 쓰고, 그 위에서 단계마다 sfcd를 **동기**로 부른다. sfcd가 답하기 전에는 다음 단계로 가지 않으므로, 컨테이너가 시작할 때는 이미 TUN·라우팅·nftables가 맞춰져 있다. 아래 값은 가상 브릿지 스레드와 맞췄다(2026-11-27).

모든 요청에 `op_id`(엔진이 같은 작업을 다시 보낼 때 같은 값)와 `boot_id`(엔진 시작마다 새 값)가 붙는다. sfcd는 이것으로 재시도인지 판단하고, 답은 적용됐다/안 됐다 중 하나로 확정한다(4xx = 적용 안 됨, 2xx = 적용됨). 엔진은 `sfc` 네트워크에 masquerade·iptables 규칙을 만들지 않는다. 전달과 NAT는 sfcd의 nft가 맡는다.

| libnetwork 단계 | 요청 | sfcd가 하는 일과 답 |
|---|---|---|
| `CreateNetwork` (bridge 장치를 만들기 전) | `POST /v1/networks/{id}/create {name, labels, options, ipam:[{subnet, gateway, ip_range}]}` | 라벨(`org.sfc.owner/kind/key/generation/spec`)과 spec hash로 소유 확인, 격리 nft·관리 게이트웨이 보호를 설치. 답 `{bridge, mtu}`: 엔진이 만들 bridge 장치 이름(`md`+12hex)과 MTU. 같은 이름 장치가 이미 있으면 엔진이 실패시킨다 |
| `CreateNetwork` 끝난 뒤 | `POST /v1/networks/{id}/created {bridge, mtu, gateway}` | 엔진이 실제로 만든 값을 한 번 돌려준다(sfcd의 사후 커널 재조회를 대신함) |
| `Join` (컨테이너 sandbox에 붙기 전) | `POST /v1/networks/{id}/join {endpoint, container_id, container_labels, addresses, mac, sandbox_key, host_veth, fixed_address}` | 그 주소의 라우팅·패킷 정책 설치. 답 `{allow, mtu, routes:[], sysctls:{}}`. `allow:false`면 컨테이너 시작 실패. `routes`·`sysctls`는 지금은 비어 있고 나중에(브릿지 예외 등) 쓴다 |
| `Leave` | `POST /v1/networks/{id}/leave {endpoint, container_id, addresses}` | 정책 제거 |
| `DeleteNetwork` (bridge 장치를 지운 뒤) | `POST /v1/networks/{id}/delete {name, labels}` | 정리. 격리 nft는 네트워크·TUN이 사라진 뒤에만 지운다 |

이 훅으로 없앨 sfcd 우회: 만들기 전 같은 이름 bridge 확인(`lookupBridge`), 만든 뒤 커널 재조회(`inspectBridgeKernel`·`matchBridge`), 보낸 여부를 모르는 오류 분류(#639의 Unknown), 옛 클러스터 잔재 사후 감지(`tunnel_foreign.go`), 컨테이너 이벤트로 임대를 맞추는 일의 일부(`docker_events.go`).

## 이미지 원천

엔진이 이미지를 받을 때 HTTP registry 대신 sfcd에 묻는다. 이미지 스레드와 맞춘 점(2026-11-27):

- 요청은 언제나 **저장소 + digest**다. 내장 registry의 blob 키와 tenant 신뢰 규칙이 저장소 기준이라, digest만으로 아무 저장소를 찾게 하지 않는다. 엔진은 `name@sha256:…` 참조에서 저장소를 그대로 넘긴다.
- tag는 노드에서 풀지 않는다(지금처럼 배포 전에 CLI·sfcd가 digest로 확정). digest 없는 pull은 엔진이 거절한다.
- 외부 이미지와 클러스터 registry 이미지도 같은 길로 준다. sfcd가 원천 자격으로 직접 읽어 넘기고, 엔진에는 자격이 가지 않는다(`internal/engine/image.go` `pullTicketed`).
- 엔진은 어떤 registry에도 접속하지 않는다. 모든 pull이 37로 sfcd에 간다(이름이 무엇이든 Docker Hub로 나가지 않음). Repository는 pull 참조의 `@` 앞 글자 그대로이고 Docker식 정규화(`docker.io/` 붙이기)를 하지 않는다. 예: `sfc-cluster-app/web@sha256:…` → `sfc-cluster-app/web`.
- 37 답: `Size`는 blob 전체 크기, 이어지는 kind 4 조각의 offset은 이 stream 안에서 0부터 센다(요청 `Offset`부터의 바이트). op는 index·manifest면 `manifest`, 그 밖(config 포함)은 `blob`.
- sfcd는 `POST /images/create?fromImage=<repo>&tag=<sha256:…>`(X-Registry-Auth 없음)로 받게 한다. `sfc-cluster-app/` 이름은 클러스터 앱용으로 비워 두고 작업 공간 저장소에 쓰지 않는다.

| 요청 | 답 |
|---|---|
| `GET /v1/images/{repository}/manifests/{digest}` | manifest 원문. 엔진이 digest를 다시 검사한다 |
| `GET /v1/images/{repository}/blobs/{digest}?offset=N` | 그 blob을 `N`바이트부터 스트림. 엔진이 digest를 검사한다. 끊기면 받은 만큼의 offset으로 이어 받는다 |

sfcd는 허락한 pull에만 답한다. Task나 빌드에 쓸 이미지를 엔진에 받으라고 하기 전에, 고정된 뿌리(`repository@sha256:…`) 하나로 pull ticket을 만든다. ticket은 뿌리의 graph를 한 번 따라가 manifest, config, layer를 모두 적어 두고, pull이 끝나면 풀린다. 저장소 이름은 정규화해서 맞춘다. 엔진은 `docker.io/library/`를 떼고 보내므로 `nginx`와 `docker.io/library/nginx`는 같은 저장소이고, tag나 digest가 붙은 이름은 `invalid`다. 클러스터 앱 이미지(`docker.io/sfc-cluster-app/<app>`)의 ticket은 sfcd가 검증한 묶음으로만 만든다(`IssueClusterApp`). 다른 pull은 이 이름으로 ticket을 만들 수 없다. 엔진 요청은 그 저장소의 살아 있는 ticket이 가진 항목일 때만 그 ticket의 원천(내장 registry, 원격 owner, 외부 원천)에서 offset부터 읽어 답한다(`internal/engineimage`, 처리기는 `internal/app/engine_image.go`). 거절 이유는 이렇다.

- `refused`: 그 저장소에 살아 있는 ticket이 없다.
- `not-found`: digest가 ticket의 graph 밖이다. blob을 manifest로 묻는 경우도 같다.
- `invalid`: 요청이 틀렸거나 offset이 항목 크기를 넘는다.
- `not-ready`: 원천을 지금 읽지 못했다. 다시 물어도 된다.

내장 registry의 blob은 offset부터 읽는다(`Blobs.GetFrom`, `OpenGraphContentAt`). 데이터는 registry run의 owner 노드에만 있으므로 다른 노드는 원격으로 받는다. 원격 길은 기존 SFCP ImageContent를 넓혀 쓴다(SFCP 스레드와 합의, purpose 23은 다시 비움). 요청은 `{Tenant, Ref(repository@digest, PinImage로 고정), Kind manifest|blob, Digest, Offset}`이고 맨 digest만으로는 받지 않는다. 받는 쪽이 작업 공간의 저장소 사용 권한과 신뢰 규칙을 확인하고, 끝나면 전체 digest를 다시 확인한다. kind 번호는 SFCP S6에서 정한다.

## 내장 BuildKit (열린 문제)

엔진의 BuildKit은 엔진 권한으로 돈다. 지금 sfcd는 빌드마다 권한 없는 짧은 buildkitd 컨테이너를 띄워 격리한다. 옮기기 전에 정할 것:

1. 빌드별 격리·자원 제한: RUN 단계는 BuildKit이 컨테이너로 돌리므로, sfcd가 빌드마다 정한 cgroup parent(메모리·CPU·pids 상한)를 엔진에 넘기는 방식을 검토한다.
2. 컨텍스트·비밀값: BuildKit session(`/session`, `/grpc`)으로 넘긴다. 엔진은 빌드가 켜진 노드에서만 이 경로를 연다(패치 0008). 접속은 sfcd만 된다(상대 확인).
3. base 이미지 신뢰 경계: BuildKit이 registry에서 직접 받지 않고 sfcd가 주는 `OCIStores`와 `SourcePolicy`로만 읽는지 시험으로 확인한다.
4. 결과: OCI exporter로 sfcd가 준 fd에 내보내고 sfcd가 registry에 게시한다. push exporter는 쓰지 않는다.
5. 캐시: 지금은 작업별 daemon이라 tenant별로 갈린다. 엔진 캐시 하나를 공유하면 tenant별 분리·정리·사용량을 새로 설계해야 한다.

## 구현 순서

1. sfcd: `/run/sfe/sfcd.sock` 수신·상대 확인·purpose 표(**됨**: SFCP 스레드 PR #692 `ListenEngine`), Runtime 연결과 처리기 표(R18 PR #673). Seafield: 연결·재접속·상대 확인·SFCP 세션(**됨**: 패치 0015).
2. 볼륨 드라이버 `sfc` (Seafield) + sfcd 볼륨 응답.
3. 네트워크 드라이버 `sfc` + sfcd 네트워크 응답.
4. 이미지 원천.
5. 내장 BuildKit으로 빌드 옮기기(위 열린 문제를 정한 뒤).

## 맡은 곳 (Seafield 총괄이 나눔, 2026-11-27 18:00 KST)

| 일 | 맡은 스레드 |
|---|---|
| 엔진 패치, sfed 쪽 purpose 32–37, wire·enginemux 사본 확인, 로그 보관소(sfcd), eventbus `engine` 발행 처리기 | Seafield 엔진(총괄) |
| `pkg/sfcp/wire`, `enginemux`, 로컬 엔진 모드, fd 싣기, purpose 표 | SFCP 구조 정리 |
| sfcd 엔진 세션 틀: purpose 32 구독·커서(boot_id, seq)·처리기 등록표, 35/36/37 처리기 등록표, engine.Client 모으기, 종료 사실로 재시작 판단 | sfcd 구조 리팩터(R18) |
| 35 볼륨 답(Mount fd 포함) | 볼륨·비밀값 |
| FUSE 공유 볼륨 RootFD, FD store 인계 | 공유 데이터 저장소 |
| 36 네트워크 답(사용자 네트워크) | 가상 브릿지 |
| 37 이미지 답, Blobs offset 읽기, 서버 행 `Build` 필드 | 이미지·빌드 |
| 37 클러스터 앱 이미지(`sfc-cluster-app/<app>`), 36 클러스터 앱 참여, node.yaml → daemon.json | CLI·yaml |
| purpose 22 `engine` topic, 웹 허브, 화면 재읽기 | 웹 실시간 반영 |
| 로그·memory·pressure·빌드·엔진 정보 화면 | 웹 프런트엔드 |
| 백업·복구 문서(엔진 상태는 클러스터 백업에 없음) | 전체 리팩터 |
| 가짜 엔진 어댑터를 Seafield 기준으로 | sfcd 구조 리팩터(R18) |
| 이름·소켓 이름 변경 | 제품 이름 변경(#691) |

### 엔진 기능을 더하거나 바꾸는 순서 (Jay 2026-11-28 13:29 KST)

1. Seafield 총괄이 가짜 엔진 어댑터(`tests/enginefake`)에 먼저 새 동작을 넣고 시험한다.
2. 담당 스레드는 그 가짜 어댑터를 상대로 sfcd 쪽을 구현한다.
3. 실제 엔진 패치는 2와 함께 진행해도 된다.
4. 기준은 언제나 실제 구현이다(Jay 13:38 KST). 가짜와 실제가 다르면 가짜를 실제에 맞춰 고친다. 가짜에만 있는 기능은 두지 않는다.

처리기는 전송과 묶지 않고 op 구조체를 받고 돌려주는 함수로 쓰고, 등록은 R18 틀에 맡긴다. 본문은 위 "프레임과 본문"을 따른다.

eventbus 사건(웹 실시간 반영 스레드와 합의): Topic `engine`. Kind `engine.container` {Tenant, App, Container, Node, Reasons}, Reasons ∈ start, stop, die, oom, pressure, health. Kind `engine.node` {Node, Reasons}, Reasons ∈ boot, lag, build. 값은 싣지 않고 참조만, 컨테이너마다 300ms 모아 한 번 발행. `eventbus.Event`에 `Container`, `Reasons []string` 필드를 더한다. Tenant 빈 컨테이너는 ManageCluster로 거른다. 구현: `internal/app/engine_bus.go`. `boot`는 사건의 boot가 바뀔 때, `lag`는 엔진 보기를 모두 다시 읽어야 할 때(새 boot나 사건 유실) 보낸다. `build`는 엔진이 빌드 사건을 내기 시작하면 더한다. `seafield.memory`는 `oom`으로 보낸다.

로그 보관소: `internal/logstore`(sfcd `StateDir/logs`). `seafield.logs` 사건과 새 boot·유실 때 컨테이너마다 33 bulk → 저장 → 34 ack. OpID·BootID는 문자열이고 각각 128바이트 이하.
