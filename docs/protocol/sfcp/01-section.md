## 메시지 목적

metadata-only artifact 요청(begin-app-upload/put-app-part/abort-app-upload)은 명령 kind `ModuleUpload`로 정확한 upload CAS를 사용한다. 모드는 action으로 정해지고 따로 서명하는 필드는 없다. 현재 member/사용자·tenant 권한·quorum·크기/개수·원 요청/epoch·전체 FSM 검증을 유지하고 미래 root는 거부한다. 다른 앱 관측의 root 변경은 이 독립 upload의 생성0/조각 revision을 대체하지 않는다. 앱 수락/이관·native 변경에 이 모드를 쓰지 않는다.

payload에 Target이 있는 `down-app`은 kind `ModuleAppDown`을 사용한다(모드는 payload Target으로 정해진다). 앱 조회의 DownTarget은 `sfc-app-down-target-1` domain과 검증된 원 app Origin 서명 대상 bytes의 SHA-256 digest다. payload Target에 이를 고정하고 원 expected/root·epoch·ID·서명을 보존한다. 현재 Origin/tenant/app·cleanup 권한과 기존 retirement 부재를 대조한 뒤 현재 Inventory revision으로 원 Retire를 호출한다. 관측만 증가한 root/revision을 허용하되 미래 좌표·다른 Origin·다른 action/namespace/actor는 거부한다. 수락은 native Gone을 뜻하지 않는다.

앱 대상 CAS의 같은 숫자 kind는 `ModuleAppCAS`로 부르며 `ModuleAppDown`은 동일 값의 별칭이다. field override/반환은 payload `Target`으로 이 모드를 선택한다. `app-cd-field`의 Target은 `sfc-app-field-target-1` domain 아래 원 등록/sync/down·policy/override revision·candidate/running/transition·현재 operation/plan/status·Task 원 참조/명령/Binding/공유 Goal의 SHA-256 지문이다. health sequence/시각·fetch ticket/오류 bookkeeping·다른 앱은 지문에 넣지 않는다. 과거 root/Delivery 좌표라도 같은 대상이면 현재 reducer의 idle/소유권·권한/후보 승인 검사를 거쳐 적용하며 미래 좌표나 다른 대상은 거부한다. 다른 action·namespace·actor·서명 변조로 이 모드를 사용할 수 없다. 실패 뒤 서명/ID를 자동 변경하지 않는다. schema와 kind의 숫자 값은 바꾸지 않는다.

인증된 managed owner의 기존 native `observe` 응답은 선택 `VolumeError`에 해당 node의 Volume worker 오류를 담을 수 있다. `ModuleError`와 구분하는 현재 진단이며 Raft 상태·작업 실패 확정·native Ready/Gone/취소 증거를 대신하지 않는다. target 준비 오류는 원 move ID와 prepare 경계를 포함하되 Secret 원문을 응답에 넣지 않는다. 이 필드 때문에 인증/조회 권한이나 schema 번호1을 바꾸지 않는다.

| 영역 | 전송/허가 | 성공의 의미 |
|---|---|---|
| 협상·상호 인증 | 제한된 reliable stream, 전체 키/클러스터·현재 정책·challenge 검증 | 그 연결의 신원/목적 허가; 투표권/관리 커밋 아님 |
| 관리 명령·결과·최신/로컬 조회 | 인증된 reliable request stream, 호출자 권한·요청 ID | 수신·제안·확정·실제 적용을 각각 명시 |
| Raft RPC | 인증 peer의 전용 논리 stream/목적, 현재 구성 검사. 요청 종류별 보낸 쪽 역할 검사([보안](../../mechanisms/security.md#raft-요청을-보낼-수-있는-역할)) | 라이브러리의 term/index/구성 규칙; 연결 수는 quorum 아님 |
| Snapshot | Raft 전용 전송 목적의 bounded stream, 포함 위치/구성/길이/hash·설치 허가 | 수신/검증과 내구 설치·ACK 분리 |
| 노드 상태·관측 | 인증된 stream, 원 노드/관측 시점·대상 결합 | 로컬 관측 보고; 임의 Desired 확정 아님 |
| IP 터널 데이터 | 인증된 QUIC DATAGRAM, Network/owner/CIDR/endpoint/MTU 한도 | 패킷 전달; 앱에서 무조건 재전송하지 않음 |
| 경로 관측 | Member와 Tunnel 허가의 reliable stream, 원 요청/scope·서명 native 예산 | 현재 경로의 양방향 관측; Raft 확정/서비스 Ready 아님 |
| 원격 Secret 값 읽기 | SecretFetch 전용 member stream·current Task/승인/provider quorum 허가 | 원 public binding/read-set의 값 전달; 일반 관리 응답/공유 원문 저장 아님 |
| lifecycle 소비 artifact | CheckerArtifact 목적13·현재 installed member·accepted use/원 app Binding·양쪽 quorum permit | 원 source/module 또는 closed build의 compiled bytes 전달. 소비 node의 실제 cache 저장 callback 뒤 ACK/최종 receipt이며 실행 Ready/관리 변경/새 job 수락이 아님 |
| lifecycle 원격 검사 | CheckerProbe 목적14·현재 installed member·원 app coordinator/대상 owner·양쪽 quorum permit | 한 원 호출의 typed private 입출력. 수신 owner의 내구 기록/종료와 송신 owner의 저장 뒤 ACK를 구분하며 복구 조회는 새 실행을 허가하지 않음 |
| 사용자 exec·연속 조회 | ContainerSession 목적15·현재 사용자 서명/권한·원 native owner·fresh quorum permit | 양방향 stdin/출력/resize·follow/watch. 원 ExecID/결과를 보존하고 단절 뒤 자동 재실행/재Attach하지 않음 |
| 노드 대화형 shell | NodeShell 목적19·현재 사용자 node-shell scope/노드 grant·현재 installed owner·quorum | 수락된 원 SessionID의 local SSH PTY만 사용. 명시 close/정책 종료는 원 사용자 ClosedBy를 보존하며 입력/화면은 복제하지 않음 |
| lifecycle 원문 staging/recover | User 목적·현재 user session/challenge·원 provider 직접 접속·quorum permit. stage는 signed descriptor와 ordered kind4/24KiB 조각·EOF | source bytes와 서명 사실의 node DB 저장/원 사실 복구. shared named 등록·문법 적합·실행 Ready가 아님 |

Raft 라이브러리는 자기 알고리즘/로그 형식을 유지할 수 있다. 어댑터는 해당 RPC를 SFCP의 승인된 논리 stream 안에 운반하고 주소·전체 키·기한·길이/동시성 예산을 결합한다. 별도 평문 TCP 포트로 fallback하지 않는다. 라이브러리 API가 이 경계를 지원하는지 Mock 이후 실제 적합성 확인에서 검증한다.

Ingress의 HTTP/1.1·2·3은 외부 요청 프로토콜이다. SFCP와 같은 세션/ALPN/신뢰 원본으로 혼합하지 않는다. HTTP/3 또는 gRPC로 SFCP를 대체하지 않는다.

