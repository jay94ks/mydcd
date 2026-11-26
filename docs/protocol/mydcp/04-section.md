## 실제 관리/전송 계약

관리 payload는 schema=1 Method/Nonce/Command/Key/Latest/Input의 정규 JSON 바이트다. signed envelope는 원 Caller32·Body·Signature64·Forwarded를 담는다. Ed25519는 `mydc-management-1 || cluster32 || Body`를 서명한다. 직접 수신은 Caller와 TLS 키가 같아야 하고 relay는 현재 member의 kind=4만 허용한다. 원 서명/현재 actor 권한을 다시 검사하며 이미 Forwarded인 요청은 다른 follower로 보내지 않는다. 응답은 원 Body SHA256/stream request에 결합한다. observe는 로컬 관측, plan은 최신 barrier 뒤 모듈의 읽기 전용 제안이며 응답 Data는 정규 JSON이다. [CLI 계약](../../configuration/cli.md)을 따른다.

관리 명령 순번과 객체 revision/generation은 실제 RaftIndex와 다른 좌표다. 응답은 CommandIndex/RaftIndex/AppliedTerm을 구분한다. local 조회를 최신/과반수 증거로 표시하지 않는다. 상태 전체를 한 128KiB 관리 응답에 넣지 않으며 get/result는 한 객체/요청의 bounded 결과다.

UDP와 quic.Transport는 MYDCP가 직접 소유한다. 동일 socket을 listen/dial에 사용하고 Close는 수락 차단·연결 종료·underlay read loop 종료·UDP close·handler 회수를 기다린다. header/body 파싱64개와 관리16/Raft32/Snapshot2/관측8개 handler permit은 분리한다. 인증5초/일반 요청30초, 연결128개·연결별 incoming stream64개·uni stream 비활성이다. Snapshot은 별도 송신/수신 하나씩 owned disk staging을 사용한다.

보고 receipt는 실제 owner handler의 성공 뒤에만 보내며 Raft 확정/서비스 적용과 다르다. Tunnel 목적 허가는 같은 일반 TUN 망의 노드 쌍 또는 같은 committed view에서 기존 RouteWork 검사를 통과한 현재 양측 승인 route owner 쌍에서 도출한다. PathControl/Packet의 coarse 허가이며 실제 scope·native·flow 검사를 대체하지 않는다. DATAGRAM은 인증된 현재 Tunnel 허가·TLS peer와 owner 일치·wire/실제 path 크기를 검사하며 앱 재전송/분할을 하지 않는다. 수신 callback 성공과 거부/누락/실패를 별도 수치로 센다. Network/endpoint/IP/MTU 업무 검사는 R3 Network의 책임이다.

노드 키 교체 뒤 Tag1은 현재 TLS Session의 peer 키와 일치해야 한다. endpoint·native journal·route 참조의 원 owner는 그대로 두고, 같은 committed Directory의 해당 자원 키 이력으로 현재 peer를 확인한다. 수신은 source IP의 원 endpoint owner와 그 owner에 허가된 현재 Session/path, 목적 endpoint 또는 원 route token을 함께 검사한다. 하나의 현재 키가 여러 과거 자원을 담당하더라도 network ID만으로 첫 plane에 전달하지 않으며 정확히 하나의 serving plane이 허용할 때만 전달한다. 옛 키로 TLS를 허용하거나 원 endpoint/flow ID를 현재 키로 다시 쓰지 않는다.

cross-tenant도 같은 Packet 목적/Network·endpoint·현재 path를 사용한다. 업무 owner의 전용 RoutePolicy는 IP/transport 방향·port와 원 양측 flow pin gate를 추가로 요구한다. Gate가 없는 plane은 시작하지 않고 수신 대기열의 원 frame도 전달 직전에 현재 gate로 다시 검사한다. handler의 Gate 조회는 내구 게시된 읽기 view만 사용하며 control/native I/O를 기다리지 않는다. 필터 설치·수신 수락을 양측 pin 저장/실제 서비스 통신 성공으로 표시하지 않는다.

### 실제 outbound 경로 예산

`Session.PacketBudget`은 같은 QUIC 연결의 public native tracer에서 ACK 기반 MTU·원격 DATAGRAM 한도·CID 길이를 받는다. 고정 quic-go v0.65.0의 native payload estimate인 `UDP MTU −37B`와 실제 short header/CID·최대4B packet number·16B tag·DATAGRAM type/2B length의 한도 중 작은 값을 사용한다. 원격 receive frame 한도도 적용한다. 처음에는1200B 기준으로 보수적으로 제한하며 `InitialPacketSize`를 강제하지 않는다. 수신/다른 연결의 MTU를 공유하지 않는다.

Packet kind=1의 고정 MYDCP 비용은120B다. IP 예산은 전체 frame 예산에서 이 비용을 뺀 값이며 optional TLV는 추가로 차감한다. 송신 직전에 전체 encoded 크기를 확인한 뒤 native `SendDatagram`이 자기 현재 한도를 다시 검사한다. `WaitPacketBudget`은 native 이벤트/취소/종료를 기다리며 별도 앱 probe·재전송·stream fallback을 만들지 않는다.

관측에는 원 인증 challenge와 연결별 active path generation이 붙는다. active tuple 전환은 이전 MTU/관측 시점을 폐기하고1200B로 돌아간다. inactive/probing tuple은 활성 관측을 바꾸지 않는다. 이 관측은 서명된 양방향 Network admission·Raft 확정·상대 서비스 건강의 증거가 아니다. 로컬 커널 경로 감시/실제 감소 복구와 TUN admission은 Network가 연결해야 한다.

실제 경계는 같은 인증 연결의 dial/accept 양방향1280B·1284B IP 크기 전달과 초과/종료 거부를 확인했다. 실제 TUN·커널 경로·Docker packet plane·경로 감소 시험의 성공으로 확대하지 않는다. 재검증 계획을 따른다.

연결의 native 경로 출처는 wire 필드가 아닌 로컬 관측이다. dial 직전/accept 직후의 실제 출력 장치·원격 주소·source/gateway·MTU를 연결 수명에 보존한다. TUN 입장은 현재 native 경로와 이를 대조하고, 변경된 연결의 PMTU 탐색 결과를 재사용하지 않는다. 실제 경로 변경에 따른 연결 retire와 fresh 인증/서명 관측을 사용하며, 관측 자체가 관리 권위나 새로운 자원 생성 허가는 아니다.


### 원 static root의 catalog 정책 활성화

Management의 readonly `catalog-policy`는 latest quorum·현재 Admin rights와 원 bootstrap full key를 모두 요구한다. Key/Input/Command·local 조회는 거부하며 public plan/현재 epoch·command index와 원 SDK 구성 index/applied floor·full-key/endpoint/voter 목록을 반환한다. SDK LogConfiguration 또는 checksum으로 검증된 native Snapshot과 durable FSM의 구성 bytes를 대조한 응답 노드의 provenance이며 다른 각 노드의 설치/가입 ACK는 아니다. 활성화는 별도 transport/RPC가 아니라 기존 signed `submit`/`result` A1 경로를 사용한다. canonical `CatalogPolicyActivation`의 domain은 `mydc-catalog-policy-activation-1\x00`이며 schema1·cluster/admin·source/target manifest·policy ID·epoch·원 request ID를 서명한다. 외부 command의 actor/epoch/ID/key/Expected0/Kind도 해당 서명 입력과 같아야 한다. 다른 cluster/manifest/권한·새 ID의 재사용은 거부한다. row 이전 로그는 기존 no-module 정책으로, 이후는 target catalog 정책으로 재생한다. 원 Unknown을 새 ID로 우회하거나 tenant User 인증으로 시스템 설치 정책을 바꾸지 않는다.

### 원 구성 adoption의 서명 metadata

새 목적/RPC/별도 합의를 만들지 않는다. plan 준비는 기존 latest Management catalog-policy 응답을 사용하며 원 admin이 `mydc-managed-adoption-plan-1\x00` domain의 schema1 plan에 서명한다. cluster/admin·source manifest/catalog manifest/policy·canonical 원 peers와 실제 NativeOrder·configuration index/최소 applied·command floor·원 epoch/operation·선택한 기존 voter genesis를 고정한다. 각 node의 offline source certificate는 `mydc-node-adoption-1\x00` domain에서 plan digest·원 peer·실제 applied/command 위치·원 state digest에 서명한다. 이는 각자의 로컬 준비/저장 관측이며 별도 과반수 인증서나 Init/Join ACK가 아니다.

공유 `control/managed-policy`는 원 plan/node facts를 canonical A1 Module command로 결합한다. same original actor/epoch/operation·Expected0를 요구하고 Members checkpoint/parts만 명시 related patch로 작성한다. source catalog/계정·native 자원/원 ID는 변경하지 않는다. metadata는 기존 command64KiB 경계를 따르며 준비 certificate를 전역 확정/managed Ready로 해석하지 않는다. source-prefix replay·동일 DB binding/config-index 및 실제 원 native 소비는 별도 전체 이행 경계다.

ManagedTransition은 같은 A1 원 actor/epoch/operation의 actual source config/index를 재검사한다. DirectCatalog는 원 로그 정책 선택에 서명된다. 정상 확정은 marker/Directory/receipt와 target binding/config-index를 같은 sync에 저장하며 source stop/restart 요구가 응답 유실/Unknown으로 관측될 수 있다. 이후 원 nonmember signer의 Management read는 exact result에 한정하고 get/새 submit은 거부한다. Managed=true의 node fact는 committed target의 로컬 준비/재시작용이며 shared adoption source로 수락하지 않는다. 별도 재전송/합의 경로는 없다.

<a id="후속-volume-transfer-경계"></a>

