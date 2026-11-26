# 끊긴 노드 간 Mesh 링크 복구

현재 RQ4 서버·CLI 연결 단계이며 마지막 실행 검증 전이다. 이 동작은 설치된 노드 쌍의 끊긴 MYDCP 멤버 연결을 기존 인증된 QUIC Dial로 복구한다. 살아 있는 inbound/outbound 경로를 강제로 닫지 않는다. TUN·Raft 멤버십·tenant 업무 권한·Task·Volume을 재생성하지 않는다.

```sh
mydc cluster mesh --all
mydc cluster reconnect node-a node-b --dry-run
mydc cluster reconnect node-a node-b
# 링크가 이미 up이어도 원 결과를 먼저 읽는다.
mydc op show ID
```

첫 인자는 실제 Dial을 수행할 owner이며 둘째 인자는 그 owner가 보는 설치된 상대 노드다. 두 값은 서로 달라야 한다. 현재 시스템 관리자(`ManageCluster`)와 credential의 `reconnect-tunnel` 허용 범위를 교차 검사한다. tenant 관리 권한만으로 실행할 수 없다. `cluster mesh`의 `PairID`는 노드 ID를 정렬한 `node-a/node-b` 형식으로 계획·결과와 같다.

## 미리보기와 수락

미리보기는 owner의 최근 서명된 `down` 관측과 현재 설치 노드 ID/키/상대 endpoint를 묶는다. up/degraded·미관측·초대만 된 노드·다른 클러스터·stale/위조 관측은 계획으로 사용하지 않는다. 같은 PairID라도 양쪽 관측은 서로 다를 수 있으므로 owner를 명시한다. 관측 신선도는 기존120초 계약이며 observation은 밀리초, 사용자 operation은 초 단위를 사용한다.

수락은 기존 User 서명 action `reconnect-tunnel`과 Raft를 사용한다. 원 요청의 operation ID·대상 키/주소·관측 지문을 보존하고 같은 쌍의 queued/running과 겹치는 새 요청은 거부한다. 계획 이후 링크가 자동 복구될 수 있으므로 실제 실행 직전에 owner가 현재 원 grant와 설치 구성을 quorum으로 확인하고 자기 실제 연결을 다시 검사한다.

CLI는 원 intent를 전송 전에 journal에 저장한다. 같은 request ID는 현재 down 상태를 다시 계획하기 전에 그 원 기록을 조회한다. `--resume-original`은 같은 서명만 명시 재개하며 원 기록이 없으면 거부한다. 다른 노드·peer·action·operation으로 바꾸거나 새 ID를 자동 발급하지 않는다.

| 공유 State | 의미 |
|---|---|
| queued | 원 사용자 요청 수락, owner 시작 보고 전 |
| running | owner 시작 확정, 원 로컬 효과/결과 정산 중 |
| done | 실제 인증된 링크를 확인한 결과가 공유 상태에 반영됨 |
| failed | 현재 권한 회수·peer 변경·실제 Dial 실패 등의 원 결과 |

`compact` 등 다른 유지보수와 마찬가지로 CLI의 `status: accepted`는 작업 수락이며 실제 링크 복구 성공이 아니다. `reconnect-status`의 결과를 확인한다.

## User 메시지·포맷

Unix 관리 소켓과 네트워크 MYDCP의 기존 User purpose/frame·Session·서명 envelope를 사용한다. 다음은 추가 본문 필드 예시이며 실제 client는 기존 Nonce와 채널 challenge 서명을 포함한다. JSON 필드는 대문자로 시작하며 schema는1이다.

```json
{"Schema":1,"Method":"tunnel-reconnect-plan","Tunnel":{"Node":"node-a","Peer":"node-b","Operation":""}}
```

```json
{"Schema":1,"Method":"tunnel-reconnect-status","Tunnel":{"Node":"","Peer":"","Operation":"link-42"}}
```

Request.Tenant/Node/After는 비워 둔다. 다른 method의 selector와 섞을 수 없다.

| Method | Reply 추가 필드 |
|---|---|
| tunnel-reconnect-plan | TunnelPlan |
| tunnel-reconnect-status | TunnelStatus |
| whoami | TunnelRootRevision, 기존 ModuleEpoch |
| 기존 operation/result | 기존 사용자 요청 Result/Found와 공개 사유 |

| TunnelPlan 필드 | 내용 |
|---|---|
| Schema, Cluster | 1, 현재 클러스터 ID |
| Node, Owner | owner 노드 ID와 설치 공개키 |
| Peer, PeerKey, Endpoint | 원 상대 노드 ID/공개키/설치 주소 |
| PairID | `mesh links`와 같은 노드 쌍 식별자 |
| Observation | 기존 observability.Report 형식의 owner 서명 down 관측. Node/Key/Index/At와 Link를 포함 |
| Target | 위 선택·관측을 묶은32바이트 지문 |

기존 `[32]byte`의 JSON은32개 숫자 배열이며 서명 바이트는 base64다. 관측과 원 사용자 승인을 혼동하지 않는다. 관측만으로는 관리 권한을 얻지 못한다.

실행은 기존 UserOperation의 `Change.Action=reconnect-tunnel`, `Expected=0`, `Payload={Operation,Plan}`을 사용한다. whoami의 TunnelRootRevision은 operation.RootRevision에 넣고 현재 module epoch·원 request ID를 서명한다. 현재 멤버 키/주소와 원 관측의 유효 범위를 다시 검사한다. 사유·사건 ID는 공개 원 metadata이며 권한을 만들지 않는다.

| TunnelStatus 필드 | 내용 |
|---|---|
| Schema, Operation, User | 1, 원 operation ID와 승인 사용자 ID |
| State, Plan | 공유 진행과 원 선택 |
| Revision, RootRevision, At | job 행 CAS·공유 root revision·최근 진행 UTC Unix 초 |
| Reason? | 공개 원 사유 |
| Result? | terminal 결과. 원 Session/grant는 반환하지 않음 |

| Result 필드 | 내용 |
|---|---|
| State | reconnected, already-connected, failed |
| PairID, HandshakeAt | 같은 원 노드 쌍과 실제 인증 시각(UTC Unix 밀리초). 실패 시 시각0 |
| KeptExisting | already-connected일 때 true. 기존 경로를 닫지 않았음 |
| Code, Error | 실패 코드와 최대512바이트 원인. 성공이면 비움 |

실행 중 다른 경로가 복구됐으면 `already-connected`로 보고한다. 이 결과를 새 Dial이 원인이었다고 표시하지 않는다. `reconnected`도 다른 background 연결과의 인과관계를 증명하는 지표가 아니라 이 원 요청이 정상 Dial을 마치고 인증된 링크를 확인한 결과다.

## 노드 실행·복구·소유권

공유 job은 시스템 관리 자원 `control/tunnel-reconnects`가 소유한다. queued/running은 owner와 peer 양쪽의 node activity·원장 회수에 outstanding 참조로 포함한다. owner의 원 private sent/result는 `maintenance/tunnel/`에 보관한다. 앱 종료·프로필 변경·연결 응답 유실로 삭제하지 않는다. job은 최대128개, 계획8KiB·결과4KiB·공유 checkpoint4MiB이며 수락 전에 pending 결과 공간을 예약한다.

노드 Management `tunnel-reconnect-work`는 `{Operation}`을 받아 Schema/Cluster/Owner/Operation/State/Expected/RootRevision/Epoch/Index/Plan/Allowed를 반환하는 quorum read다. `tunnel-reconnect-report`는 `{Schema,Cluster,Owner,Operation,Action,Expected,RootRevision,Epoch,At,Result?,Signature}`를 받는다. Action은 begin/finish/cancel이며 해당 원 owner만 보고한다. 서명은 `mydc-tunnel-report-1` 뒤 NUL과 Signature를 null로 둔 JSON이다. Unix 사용자 연결에 이 노드 보고 권한을 부여하지 않는다.

owner는 private sent를 동기 기록한 뒤 현재 grant로 기존 Transport.Dial을 호출한다. 저장 실패 시 Dial하지 않는다. 일반 Dial은15초의 유한 예산을 사용하며 실제 오류를 실패로 남긴다. daemon 종료 중 응답이 사라졌으면 원 sent를 유지한다. 재개 시 같은 원 쌍의 긍정적인 인증 연결을 먼저 관측하고, 없다면 현재 원 grant가 유효할 때만 멱등 복구 Dial을 이어갈 수 있다. 권한 회수 뒤 새 Dial은 금지하며 관측 부재를 미실행 증거로 바꾸지 않는다.

`done`은 해당 시점의 실제 링크 관측이다. 지속 가용성·패킷 전달·가상망 정책·tenant 통신 허용을 보장하지 않는다. 후속 끊김은 같은 PairID의 관측/이벤트로 다룬다.
