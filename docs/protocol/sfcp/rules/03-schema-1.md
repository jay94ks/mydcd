## schema=1 바이트 계약

앱 범위 검사도 기존 Management app-progress의 owner 서명 Observation.AppChecks를 사용한다. 정확한 원 FrozenProgram/coordinator·결과 만료를 확인하고 전체 앱 건강/완료에만 적용한다. optional OwnerBoot는 runtime TLS certificate hash이며 커널 boot 증거가 아니다. 원격 Dependency는 기존 공유 서비스 관측을 소비하고, 아직 연결하지 않은 원격 native Probe를 로컬 API나 비인증 경로로 우회하지 않는다. nil optional 필드는 기존 바이트에서 생략한다.

선택 `Observation.LogDriver`는 task owner가 실제 Docker Inspect로 확인한 driver/plugin 이름이다. task 종류에만 허용하며 같은 native의 알려진 driver는 변경할 수 없다. legacy 미관측의 보완과 실제 종료 관측의 live metadata 생략은 구분한다. 기존 schema1에서는 생략해 원 서명을 유지한다. 유한 container-observe도 선택 LogDriver를 전달하지만 logger backend options/credential을 보내지 않는다. 명시 로그 삭제/재생성은 같은 원 Task/사용자 승인을 사용하는 별도 작업이다.

기존 Management의 app-progress owner 서명 Observation은 optional StartedAt/TaskRestart로 정책 재시작을 보고한다. 원 FrozenProgram·Task/native/owner·completed 검사 제어 receipt와 이전 exit를 대조하며 같은 실행의 receipt는 heartbeat에서 보존한다. 별도 purpose/관리 명령·비인증 경로를 만들지 않고, 이 필드가 없으면 기존 JSON/서명 bytes를 유지한다. native 상태 변경 허가는 현재 binding/tenant 정책과 quorum 경계에서 별도로 확인한다.

고정 header는 24B다. `MDG1[4] | schema:u16=1 | purpose:u8 | kind:u8 | reserved:u32=0 | request:u64 | bodyLength:u32` 순서이며 정수는 LE다. purpose는 Handshake=1, Management=2, Raft=3, Snapshot=4, Observation=5, Packet=6, PathControl=7, User=8, Membership=9, SecretInput=10, SecretFetch=11, VolumeTransfer=12, CheckerArtifact=13, CheckerProbe=14, ContainerSession=15, ImageContent=16, CertificateMaterial=17, VolumeFile=18, NodeShell=19, ClusterBackup=20, VaultValue=21, ChangeWatch=22, VolumeFS=24이다. 25는 Transit으로 예약했다. request는 일반 frame에서 0이 아니며 Packet에서만 0이다. request의 실제 pending table/동시성 예산은 실제 전송 owner가 관리한다.

body는 `tag:u16 | flags:u16 | length:u32 | bytes`의 오름차순 TLV다. flags는 optional=0/required=1만 허용한다. 알려진 필수 field는 1부터 연속이며 누락/중복/역순을 거부한다. optional 확장은 tag≥128이고 frame당 전체 field는 32개 이하다. 알 수 없는 required 확장은 거부한다.

kind 번호는 모든 purpose에서 같은 뜻이다: 1 요청, 2 응답, 3 member relay, 4 데이터 조각, 5 duplex record, 6 끝(EOF), 7 저장 ACK, 8 최종 ACK, 16부터 purpose 고유(`internal/sfcp/kinds.go`). Handshake와 Packet만 따로 번호를 쓴다.

| purpose / kind | 필수 tag 순서와 길이 | body 예산 |
|---|---|---|
| Handshake / 1 hello, 2 proof | 1 공개키32, 2 cluster32, 3 challenge32; proof는 4 서명64 추가. hello의 선택 확장: 128 빌드 버전, 129 기능 집합(u64 LE) | 4KiB |
| Management / 1 command, 2 result, 3 relay, 16 read | 1 정규 payload, 2 명령/요청 digest32 | 128KiB |
| Raft / 1 RPC, 2 RPC 응답 | 1 라이브러리 RPC payload | 256KiB |
| Snapshot / 1 metadata | 1 위치/구성/길이 metadata, 2 artifact digest32 | 4KiB |
| Snapshot / 4 chunk | 1 offset8, 2 조각 bytes, 3 artifact digest32(모든 조각이 같은 모양) | 128KiB+64B |
| Snapshot / 8 installed | 1 index8, 2 term8, 3 artifact digest32 | 128B |
| Observation / 16 작업량 보고, 17 노드 관측, 18 진단 사건 묶음, 19 앱 관측 갱신(리더에게) | 1 같은 kind 항목 하나 이상: 항목마다 `u32 LE 길이 | bytes`. 받는 쪽은 본문을 엿보지 않고 kind로 나누며 항목마다 처리한다 | 64KiB |
| Observation / 2 receipt | 1 원 payload SHA256:32, 선택 128 거부한 항목 bitmap(항목 i는 byte i/8의 bit i%8). 거부한 항목만 버리고 나머지는 받은 것이다 | 2KiB |
| ContainerSession / 1 사용자, 2 응답, 3 member relay | 1 Envelope/reply JSON, 2 원 요청 Envelope SHA256:32 | 128KiB |
| ContainerSession / 5 record | 1 SessionRecord JSON, 2 원 서명된 Intent.Digest:32 | 128KiB |
| NodeShell / 1 사용자, 2 응답, 3 member relay | 1 Envelope/NodeShellReply JSON, 2 원 요청 Envelope SHA256:32 | 128KiB |
| NodeShell / 5 record | 1 NodeShellRecord JSON, 2 원 NodeShellRequest Body SHA256:32 | 128KiB |
| ImageContent / 1 사용자, 2 응답, 3 member relay | 1 Envelope/ContentReply JSON, 2 원 요청 Envelope SHA256:32 | 128KiB |
| ImageContent / 16 수락 빌드의 source-owner 읽기, 17 엔진용 member 읽기(4.9, 처리기는 아직 없음) | 1 ImageBuildBaseContentRequest를 담은 Envelope, 2 Envelope SHA256:32 | 128KiB |
| ImageContent / 4 data | 1 offset LE u64:8, 2 data, 3 원 요청 Envelope SHA256:32 | 24KiB+64B |
| Packet / 1 DATAGRAM | 고정 머리 40B(위 TLV 아님, [Packet 머리](04-section.md)): network16, endpoint16, IP bytes. 송신 키는 연결의 peer 키 | 65535+40B |
| Packet / 2 route DATAGRAM | 같은 고정 머리: network16, 양측 원 flow token16, IP bytes | 65535+40B |
| PathControl / 1 request, 2 response | 1 정규 PathSample JSON, 2 payload SHA256:32 | 4KiB |
| SecretFetch / 1 read, 2 response | 1 private-purpose payload, 2 원 public 요청 SHA256:32 | 128KiB |
| VolumeTransfer / 1 request | 1 정규 원 작업/artifact/offset/prefix/기한, 2 요청 digest32 | 32KiB |
| VolumeTransfer / 4 chunk | 1 offset8, 2 data≤128KiB, 3 요청/offset/data digest32 | 128KiB+64B |
| VolumeTransfer / 7 chunk ACK | 1 내구 offset8, 2 원 요청 digest32 | 64B |
| VolumeTransfer / 6 EOF, 8 verified ACK | 1 전체 bytes8, 2 artifact digest32, 3 원 요청 digest32 | 128B |
| CheckerProbe / 1 request | 1 schema1/action/metadata/원 payload hash·길이/기한 JSON, 2 해당 header SHA256:32 | 128KiB |
| CheckerProbe / 4 chunk(요청 쪽 payload, 응답 쪽 결과) | 1 정확한 offset8, 2 data≤24KiB, 3 원 header SHA256:32 | 24KiB+64B |
| CheckerProbe / 2 response metadata | 1 schema1/Closed/응답 hash·길이 JSON, 2 원 header SHA256:32 | 2KiB |
| CheckerProbe / 6 end(양쪽), 7 stored ACK, 8 final ACK | 1 해당 전체 payload SHA256:32, 2 원 header SHA256:32 | 128B |

PathSample은 schema=1·Cluster·From/To 전체 키·Scope(1–1024B)·원 Request digest·요구 MTU·표본 At(ms)·native PacketBudget·Signature다. 서명은 Signature=nil인 정규 JSON 앞에 `sfc-path-sample-1\0` domain을 붙인다. 요청의 Request digest는0, 응답은 원 서명 요청 전체 정규 JSON의 SHA256이다. 양쪽 표본은 같은 scope/요구 MTU·원 authenticated 연결의 challenge/경로 세대와 native ACK 관측을 사용한다. 수락 시30초 freshness·현재 Member/Tunnel과 업무 scope를 검사한다. 목적별 동시8 stream과 공통 요청 기한을 유지하며 다른 보고 handler를 우회/교체하지 않는다.

최상위 body 한도는 256KiB이며 decoder 생성 시 더 작은 예산도 지정할 수 있다. Feed는 frame 하나까지 소비하고 나머지 바이트 수명을 caller에게 남긴다. 반환한 body는 다음 Feed로 덮어쓰지 않는다. 손상 후 stream 재동기화를 시도하지 않는다. 실제 QUIC DATAGRAM 한도는 이 wire 한도와 별개이며 path/MTU 정책의 더 작은 값을 적용한다.

관리 변경 payload는 [명령 codec](../../../../internal/cluster/state/codec.go)의 `schema:u8=1 | kind:u8 | rights:u8 | delete:u8 | epoch:u64 | expected:u64` 뒤 Actor/RequestID/Key/Value/Target의 `length:u32+bytes`다. 키·호출자는 정규 문자열, Value는 바이트다. CAS는 객체/정책 revision이며 요청 digest는 같은 Command의 정규 Digest를 사용한다. result/read·Raft 라이브러리 payload·Snapshot metadata·관측 payload의 실제 어댑터 schema와 원 호출자 전달 증거는 R2–R4에서 연결한다. opaque payload를 decode했다는 이유로 해당 업무를 실행하지 않는다.

CD source/controller의 `ModuleReport`는 서명된 `TargetCAS=true`·`Target=app-delivery`로 `control/apps`의 인증된 node 보고만 대상으로 한다. optional signed Target이 없으면 같은 CD revision을, 있으면 고정 source/실행 의도 지문을 검사하고 원 ticket/upload·현재 action/choice를 typed reducer가 검증하므로 무관한 Apps root 변화는 진행을 막지 않는다. root의 미래 좌표·실제 대상 변경·서명/현재 정책·권한/회원/epoch·원 보고 floor 거부는 유지한다. 기존 TargetCAS 없는 보고는 원 exact root CAS와 정규 bytes/서명/ID 그대로 해석한다. schema/kind 번호는1의 기존 값을 유지한다.


command kind는 Mutate=0·SetRights=1·RotateLedger=2·Module=3이다. Module은 명시 활성화한 typed reducer만 처리하고 일반 Mutate는 `control/` metadata를 쓸 수 없다. 현재 [catalog 경계](../../../../internal/cluster/control/catalog.go)의 Key는 `control/access`, Value는 정규 JSON `Schema/Action/Principal/Expected/Payload`다. Action은 enroll/put-user/create-tenant/set-nodes/set-membership/set-trust/revoke-session이며 Payload는 action별 고정 타입으로 엄격 검사한다. 내부 Expected는 대상 user/tenant/membership의 정책 revision이고 reducer가 이것으로 CAS한다. 사용자 명령의 command Expected(root revision)는 지금 root보다 크지 않으면 받는다. 다른 사용자가 catalog의 다른 기록을 바꿔 root가 옮겨도 내 명령은 막히지 않는다. Principal은 선택 힌트이며 현재 등록된 enabled private-key와 원 인증 Actor가 일치해야 한다. node genesis 권한만으로 user 역할을 부여하지 않는다. 로그인/session adapter는 사용자 목적과 현재 catalog 권한 경계에 연결된다. 실제 부분 근거는 빈 catalog/명시 등록·원 결과/CAS·큰 checkpoint·복구와 daemon 활성화 범위다.

**빌드 버전.** 서버는 hello의 선택 tag 128에 자기 빌드 버전(`major.minor.build` 또는 `major.minor.0-dev`, 64바이트까지, a–z0–9 `.+-`)을 싣는다. 없거나 모양이 틀리면 검사하지 않는다. 상대의 major가 다르면 양쪽이 서로의 hello를 본 뒤 연결을 끊는다(`ErrMajor`, 받는 쪽은 자기 hello를 보낸 뒤 끊어 상대도 버전을 본다). 양쪽 로그에 상대 이름과 두 버전을 한 번 남기고, 같은 major에서 버전만 다르면 연결하고 한 번 정보 로그를 남긴다. 세션은 `Session.PeerVersion()`으로 읽는다. 거는 쪽은 평소 backoff로 다시 시도하므로 한쪽을 올리면 붙는다.

**기능 집합(feature set).** major마다 기능 표(`internal/buildinfo/features.go`)를 둔다. 기능 하나는 그룹(u8)·집합(u8)·버전(u16, 1부터)과 접미사로, `network-transit-v1`, `network-transit-v1-preview`처럼 적는다. 세 숫자는 32비트 코드 `group<<24 | set<<16 | version`이 된다. 한 번 붙인 번호와 이름은 그 major 안에서 바꾸거나 다시 쓰지 않는다. 서버는 hello의 선택 tag 129에 자기가 알리는 기능을 싣는다: 기능마다 코드 u32 LE, 접미사 길이 u8, 접미사 바이트(소문자로 시작하는 a–z0–9, 16바이트까지. 접미사는 대소문자를 구분하지 않고 소문자로만 적는다). 코드·접미사 순으로 정렬하고 중복 없이 64개까지인 정규형만 받는다. 없거나 정규형이 아니면 major의 기본값(기능 없음)으로 본다. 접미사가 없으면 `mainline`으로 보고 적지 않는다. 두 기능은 접미사가 같을 때만 맞는다: mainline은 코드 범위로 비교하고, 다른 접미사는 코드와 접미사가 정확히 같아야 한다. purpose 표가 purpose·kind마다 필요한 mainline 버전 범위를 적고, 양쪽 공통 집합이 그 범위 안의 버전을 가졌을 때만 보낸다(`Session.Supports`, 아니면 `ErrUnsupported`로 보내지 않음). 받는 쪽 Gate도 공통 집합이 필요 범위에 닿지 않는 frame을 거절한다. 클러스터 교집합은 구성원 세션이 들고 날 때 메모리에서 다시 계산해 캐시하며(`Transport.ClusterFeatures`), 끊긴 구성원은 마지막으로 알린 값으로, 이 프로세스가 시작한 뒤 한 번도 못 본 구성원은 빈 집합으로 센다(upgrades.md 3-4). Raft에는 두지 않는다.

proof 코어는 표준 Ed25519로 `sfc-go-auth-1 || fullKey32 || cluster32 || challenge32`를 검증한다. 키는 실제 TLS 키와 같아야 하며 fresh challenge/cluster·현재 승인 전체 키를 검사한다. Gate는 인증 전 Handshake만, 인증 뒤 현재 목적 권한만 허용하고 모든 0-RTT를 거부한다. 관리 변경·읽기·서버 결과 응답 권한은 서로 구분한다. 결과는 별도로 pending request/명령 digest에 결합한다. stream 목적도 고정한다. Raft admission은 승인된 member를 검사하며 non-voter도 포함한다. 투표권과 RPC의 term/commit 적합성은 라이브러리가 판단한다.

