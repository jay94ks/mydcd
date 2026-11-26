## schema=1 바이트 계약

앱 범위 검사도 기존 Management app-progress의 owner 서명 Observation.AppChecks를 사용한다. 정확한 원 FrozenProgram/coordinator·결과 만료를 확인하고 전체 앱 건강/완료에만 적용한다. optional OwnerBoot는 runtime TLS certificate hash이며 커널 boot 증거가 아니다. 원격 Dependency는 기존 공유 서비스 관측을 소비하고, 아직 연결하지 않은 원격 native Probe를 로컬 API나 비인증 경로로 우회하지 않는다. nil optional 필드는 기존 바이트에서 생략한다.

선택 `Observation.LogDriver`는 task owner가 실제 Docker Inspect로 확인한 driver/plugin 이름이다. task 종류에만 허용하며 같은 native의 알려진 driver는 변경할 수 없다. legacy 미관측의 보완과 실제 종료 관측의 live metadata 생략은 구분한다. 기존 schema1에서는 생략해 원 서명을 유지한다. 유한 container-observe도 선택 LogDriver를 전달하지만 logger backend options/credential을 보내지 않는다. 명시 로그 삭제/재생성은 같은 원 Task/사용자 승인을 사용하는 별도 작업이다.

기존 Management의 app-progress owner 서명 Observation은 optional StartedAt/TaskRestart로 정책 재시작을 보고한다. 원 FrozenProgram·Task/native/owner·completed 검사 제어 receipt와 이전 exit를 대조하며 같은 실행의 receipt는 heartbeat에서 보존한다. 별도 purpose/관리 명령·비인증 경로를 만들지 않고, 이 필드가 없으면 기존 JSON/서명 bytes를 유지한다. native 상태 변경 허가는 현재 binding/tenant 정책과 quorum 경계에서 별도로 확인한다.

고정 header는 24B다. `MDG1[4] | schema:u16=1 | purpose:u8 | kind:u8 | reserved:u32=0 | request:u64 | bodyLength:u32` 순서이며 정수는 LE다. purpose는 Handshake=1, Management=2, Raft=3, Snapshot=4, Observation=5, Packet=6, PathControl=7, User=8, Membership=9, SecretInput=10, SecretFetch=11, VolumeTransfer=12, CheckerArtifact=13, CheckerProbe=14, ContainerSession=15, ImageContent=16, CertificateMaterial=17, VolumeFile=18, NodeShell=19다. request는 일반 frame에서 0이 아니며 Packet에서만 0이다. request의 실제 pending table/동시성 예산은 실제 전송 owner가 관리한다.

body는 `tag:u16 | flags:u16 | length:u32 | bytes`의 오름차순 TLV다. flags는 optional=0/required=1만 허용한다. 알려진 필수 field는 1부터 연속이며 누락/중복/역순을 거부한다. optional 확장은 tag≥128이고 frame당 전체 field는 32개 이하다. 알 수 없는 required 확장은 거부한다.

| purpose / kind | 필수 tag 순서와 길이 | body 예산 |
|---|---|---|
| Handshake / 1 hello, 2 proof | 1 공개키32, 2 cluster32, 3 challenge32; proof는 4 서명64 추가 | 4KiB |
| Management / 1 command, 2 result, 3 read, 4 relay | 1 정규 payload, 2 명령/요청 digest32 | 128KiB |
| Raft / 1 RPC | 1 라이브러리 RPC payload | 256KiB |
| Snapshot / 1 metadata | 1 위치/구성/길이 metadata, 2 artifact digest32 | 4KiB |
| Snapshot / 2 chunk | 1 offset8, 2 조각 bytes | 128KiB+32B |
| Snapshot / 3 installed | 1 index8, 2 term8, 3 artifact digest32 | 128B |
| Observation / 1 report | 1 보고 payload | 64KiB |
| Observation / 2 receipt | 1 원 payload SHA256:32 | 128B |
| ContainerSession / 1 사용자, 2 응답, 3 member relay | 1 Envelope/reply JSON, 2 원 요청 Envelope SHA256:32 | 128KiB |
| ContainerSession / 5 record | 1 SessionRecord JSON, 2 원 서명된 Intent.Digest:32 | 128KiB |
| NodeShell / 1 사용자, 2 응답, 3 member relay | 1 Envelope/NodeShellReply JSON, 2 원 요청 Envelope SHA256:32 | 128KiB |
| NodeShell / 5 record | 1 NodeShellRecord JSON, 2 원 NodeShellRequest Body SHA256:32 | 128KiB |
| ImageContent / 1 사용자, 2 응답, 3 member relay | 1 Envelope/ContentReply JSON, 2 원 요청 Envelope SHA256:32 | 128KiB |
| ImageContent / 5 수락 빌드의 source-owner 읽기 | 1 ImageBuildBaseContentRequest를 담은 Envelope, 2 Envelope SHA256:32 | 128KiB |
| ImageContent / 4 data | 1 offset LE u64:8, 2 data, 3 원 요청 Envelope SHA256:32 | 24KiB+64B |
| Packet / 1 DATAGRAM | 1 현재 송신 인증 키32, 2 network16, 3 endpoint16, 4 IP bytes | 65535+128B |
| Packet / 2 route DATAGRAM | 1 현재 송신 인증 키32, 2 network16, 3 양측 원 flow token16, 4 IP bytes | 65535+128B |
| PathControl / 1 request, 2 response | 1 정규 PathSample JSON, 2 payload SHA256:32 | 4KiB |
| SecretFetch / 1 read, 2 response | 1 private-purpose payload, 2 원 public 요청 SHA256:32 | 128KiB |
| VolumeTransfer / 1 request | 1 정규 원 작업/artifact/offset/prefix/기한, 2 요청 digest32 | 32KiB |
| VolumeTransfer / 2 chunk | 1 offset8, 2 data≤128KiB, 3 요청/offset/data digest32 | 128KiB+64B |
| VolumeTransfer / 3 chunk ACK | 1 내구 offset8, 2 원 요청 digest32 | 64B |
| VolumeTransfer / 4 EOF, 5 verified ACK | 1 전체 bytes8, 2 artifact digest32, 3 원 요청 digest32 | 128B |
| CheckerProbe / 1 request | 1 schema1/action/metadata/원 payload hash·길이/기한 JSON, 2 해당 header SHA256:32 | 128KiB |
| CheckerProbe / 2 request chunk, 5 response chunk | 1 정확한 offset8, 2 data≤24KiB, 3 원 header SHA256:32 | 24KiB+64B |
| CheckerProbe / 4 response metadata | 1 schema1/Closed/응답 hash·길이 JSON, 2 원 header SHA256:32 | 2KiB |
| CheckerProbe / 3 request end, 6 response end, 7 stored ACK, 8 final ACK | 1 해당 전체 payload SHA256:32, 2 원 header SHA256:32 | 128B |

PathSample은 schema=1·Cluster·From/To 전체 키·Scope(1–1024B)·원 Request digest·요구 MTU·표본 At(ms)·native PacketBudget·Signature다. 서명은 Signature=nil인 정규 JSON 앞에 `mydc-path-sample-1\0` domain을 붙인다. 요청의 Request digest는0, 응답은 원 서명 요청 전체 정규 JSON의 SHA256이다. 양쪽 표본은 같은 scope/요구 MTU·원 authenticated 연결의 challenge/경로 세대와 native ACK 관측을 사용한다. 수락 시30초 freshness·현재 Member/Tunnel과 업무 scope를 검사한다. 목적별 동시8 stream과 공통 요청 기한을 유지하며 다른 보고 handler를 우회/교체하지 않는다.

최상위 body 한도는 256KiB이며 decoder 생성 시 더 작은 예산도 지정할 수 있다. Feed는 frame 하나까지 소비하고 나머지 바이트 수명을 caller에게 남긴다. 반환한 body는 다음 Feed로 덮어쓰지 않는다. 손상 후 stream 재동기화를 시도하지 않는다. 실제 QUIC DATAGRAM 한도는 이 wire 한도와 별개이며 path/MTU 정책의 더 작은 값을 적용한다.

관리 변경 payload는 [명령 codec](../../../internal/cluster/state/codec.go)의 `schema:u8=1 | kind:u8 | rights:u8 | delete:u8 | epoch:u64 | expected:u64` 뒤 Actor/RequestID/Key/Value/Target의 `length:u32+bytes`다. 키·호출자는 정규 문자열, Value는 바이트다. CAS는 객체/정책 revision이며 요청 digest는 같은 Command의 정규 Digest를 사용한다. result/read·Raft 라이브러리 payload·Snapshot metadata·관측 payload의 실제 어댑터 schema와 원 호출자 전달 증거는 R2–R4에서 연결한다. opaque payload를 decode했다는 이유로 해당 업무를 실행하지 않는다.

CD source/controller의 `ModuleReport`는 서명된 `TargetCAS=true`·`Target=app-delivery`로 `control/apps`의 인증된 node 보고만 대상으로 한다. optional signed Target이 없으면 같은 CD revision을, 있으면 고정 source/실행 의도 지문을 검사하고 원 ticket/upload·현재 action/choice를 typed reducer가 검증하므로 무관한 Apps root 변화는 진행을 막지 않는다. root의 미래 좌표·실제 대상 변경·서명/현재 정책·권한/회원/epoch·원 보고 floor 거부는 유지한다. 기존 TargetCAS 없는 보고는 원 exact root CAS와 정규 bytes/서명/ID 그대로 해석한다. schema/kind 번호는1의 기존 값을 유지한다.


command kind는 Mutate=0·SetRights=1·RotateLedger=2·Module=3이다. Module은 명시 활성화한 typed reducer만 처리하고 일반 Mutate는 `control/` metadata를 쓸 수 없다. 현재 [catalog 경계](../../../internal/cluster/control/catalog.go)의 Key는 `control/access`, Value는 정규 JSON `Schema/Action/Principal/Expected/Payload`다. Action은 enroll/put-user/create-tenant/set-nodes/set-membership/set-trust/revoke-session이며 Payload는 action별 고정 타입으로 엄격 검사한다. command Expected는 root의 A1 revision, 내부 Expected는 대상 user/tenant/membership의 정책 revision이다. Principal은 선택 힌트이며 현재 등록된 enabled private-key와 원 인증 Actor가 일치해야 한다. node genesis 권한만으로 user 역할을 부여하지 않는다. 로그인/session adapter는 사용자 목적과 현재 catalog 권한 경계에 연결된다. 실제 부분 근거는 빈 catalog/명시 등록·원 결과/CAS·큰 checkpoint·복구와 daemon 활성화 범위다.

proof 코어는 표준 Ed25519로 `mydc-go-auth-1 || fullKey32 || cluster32 || challenge32`를 검증한다. 키는 실제 TLS 키와 같아야 하며 fresh challenge/cluster·현재 승인 전체 키를 검사한다. Gate는 인증 전 Handshake만, 인증 뒤 현재 목적 권한만 허용하고 모든 0-RTT를 거부한다. 관리 변경·읽기·서버 결과 응답 권한은 서로 구분한다. 결과는 별도로 pending request/명령 digest에 결합한다. stream 목적도 고정한다. Raft admission은 승인된 member를 검사하며 non-voter도 포함한다. 투표권과 RPC의 term/commit 적합성은 라이브러리가 판단한다.

