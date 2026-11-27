## 노드 shell — purpose19

노드 shell 정책/상태는 기존 User=8의 `node-shell-policy|node-shell-sessions`로 읽는다. sessions는 top-level `State?`(open/closed/빈 전체)·`Node?`·`After?`를 사용하며 open은 queued/opened/closing이다. 현재 사용자·노드별 closed 최근200개·조건을 적용한 뒤 Total/Next를 계산하고 원 결과/이벤트는 보존한다. `set-node-shell-policy|set-node-shell-node|set-node-shell-grant|open-node-shell|close-node-shell`은 기존 사용자 서명 operation/result/resume와 Raft의 `control/node-shell` checkpoint를 사용한다. 정책 기본값·grant·한도·현재 권한은 [노드 shell](../../reference/node-shell.md), 전체 필드/메시지는 [Unix API](../../reference/unix-sockets/20-shell-purpose19.md)가 공통 기준이다. 이 API는 app.yaml/tenant cluster.yaml과 별도의 node 운영 권한이다.

신규 NodeShell=19 kind1은 `Envelope{Body,Session,Signature}`이고 Body는 `NodeShellRequest{Schema:1,SessionID,Nonce:[32]byte}`다. 원 user proof는 연결 challenge/Body에 고정한다. kind3은 현재 member가 이 Body/proof를 바꾸지 않고 signed Relay를 붙이는 node 간 경로다. Unix는 kind3을 받지 않는다. 초기 kind2는 `NodeShellReply{Schema:1,Code,Session?}`이며 ready만 열린 원 Session metadata를 포함한다. 요청/응답의 TLV2는 그 연결의 **원 Envelope digest**다.

ready 뒤 kind5의 `NodeShellRecord{Schema:1,Sequence,Kind,Data?,Cols?,Rows?,End?}`는 같은 wire Request와 **원 Body digest**에 결합한다. 두 방향 Sequence는 독립적으로 1부터 증가하며 client의 stdin/resize/half-close·양방향 ping·server의 stdout/end만 허용한다. Data 최대24KiB, Cols/Rows 각1–1000, frame body128KiB다. 입력 EOF인 half-close 뒤에도 출력은 계속 수신하며, 중복/역순·방향 위장·end 후 record를 거부한다. Unix 바깥 record Contract1과 reliable QUIC stream이 같은 frame/payload를 운반하고 별도 raw TCP/SSH 외부 끝점으로 fallback하지 않는다.

End는 `{Code:0..255,Reason:"exit"|"idle"|"closed"|"policy",ClosedBy?:{User,Username}}`다. closed/policy에는 서명된 원 close/권한 변경을 승인한 사용자의 ClosedBy가 필수이고 exit/idle에는 없다. 원 SessionID는 open UserOperation.RequestID이며 wire 교환 번호와 구분한다. 재시도/단절/신원 교체로 원 ID·수락 owner·준비 서명·SSH receipt를 재작성하거나 자동 재attach/새 SSH 실행을 하지 않는다. 현재 설치 키는 자기 원 기록 정산을 할 수 있지만 구키를 현재 TLS/발급 권한으로 복원하지 않는다.

현재 node-shell permit와 owner/report는 기존 인증 member Management `node-shell-owner-view|node-shell-permit|node-shell-report`를 사용한다. 외부 SSH 실행 직전과 계속 실행 시 현재 사용자/credential·issuer·정책/grant·quorum과 신선한 own-node readiness를 확인한다. policy/report·사용량은 metadata이며 화면/입력/SSH private key를 Raft에 넣지 않는다. 실제 SSH는 대상 daemon의 loopback 서버와 root 소유 Ed25519 host pin·전용 non-root 계정/키로 연결한다.

최초 header는 기존30초 제한, 사용자/owner 수립·인증 조회는10초, 채널은 read-idle60초/write5초·원 session 만료, node-shell handler64개를 적용한다. ping10초는 stream 유휴만 유지하며 제품 idle은 실제 byte 이동으로 계산한다. 정상 End 없는 EOF나 부분 전송은 원 작업의 미실행/정상 종료 증거가 아니다. `node-shell-denied|node-shell-opened|node-shell-closed` 이벤트의 공개 Detail은 원 Actor/Operation·Reason/ExitCode·선택 BytesIn/BytesOut/ClosedBy만 담고 0/nil 신규 필드는 생략한다.

