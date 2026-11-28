# 노드·디스크·Mesh·Raft 관측

이 조회는 관리 변경과 실행 권한을 부여하지 않는다. 현재 Read 권한·tenant의 허용 node·노드 서명·마지막 관측을 서버가 검사한다.

## 메시지와 범위

Unix·네트워크 SFCP 모두 User kind1의 Request/Envelope를 사용한다. `raft-status` 말고는 [typed method](unix-sockets/10-user.md#typed-method)라 선택자는 `Params`에, 응답은 `Data`에 그 method의 타입 하나로 실린다. 공통 Schema/Nonce·현재 Session·연결 challenge 서명이 필요하다.

| Method | 선택자 | 현재 권한·응답 |
|---|---|---|
| `node-summary` | `Params:{Tenant?,Node?,After?}` | Tenant 없으면 system-admin/ManageCluster. 있으면 해당 tenant Read와 허용 node. `Data:{Nodes,Next,RootRevision,CanAcceptChanges}` |
| `node-disks` | `Params:{Tenant?,Node?,After?}` | 전체는 system-admin/ManageCluster. tenant는 ManageVolumes와 허용 node·저장 root. `Data:{Disks,Next,RootRevision}` |
| `node-tenant-usage` | `Params:{Node,After?}` | system-admin/ManageCluster. 한 노드의 tenant별 사용량을 `Data:{Usage,Next,RootRevision}`로 분할 |
| `mesh-links` | `Params:{Tenant?,Node?,After?}` | 전체는 system-admin/ManageCluster. tenant Read는 허용 node 사이의 상태 요약만. `Data:{Links,Next,RootRevision}` |
| `raft-status` | 선택 After, Tenant/Node 금지 | system-admin/ManageCluster. 응답한 노드의 로컬 합의 진단인 `RaftStatus` |

node-summary·디스크·Mesh·tenant 사용량은8행씩 반환한다. 관측·Members/Catalog/Resources/저장 root·사용자/서명 scope·전체 필터에 cursor를 결합한다. basis가 달라지면 `conflict`다. 디스크 페이지는 큰 mount 경로/등록 이름을 포함할 수 있으므로 전체 행 JSON 합계120KiB도 적용한다. 숨긴 node의 총개수나 페이지 위치를 내보내지 않는다.

관측의 `ObservedAt`, `ObservationMaxAge`, 연결 시각은 **Unix 밀리초**다. 현재 관측 신선도 한도는120,000ms다. 사용자 Session·관리 operation의 Unix초와 구분한다.

## 관측이 서버 사이를 오가는 길

서버는 자기 관측을 SFCP Topic 채널(purpose 26)의 `obs/<서버>/<T-obs-src>[/…]`에 발행하고, 읽을 일이 있는 서버만 구독한다.

- 위 조회를 받은 서버는 모든 정식 구성원의 `obs/#`를 구독하고, 각 서버가 지금 값을 다시 발행해 맞춰질 때까지 최대 2초 기다린다. 세션이 없는 서버는 기다리지 않는다. 구독은 마지막 조회 뒤 150초 동안 남아, 이어지는 조회는 기다리지 않는다.
- report 이벤트를 보는 사용자 watch(웹 화면, AI 기능)가 열려 있는 동안 그 서버는 `obs/#`를 push로 늘 구독한다.
- 발행은 내용이 바뀌었거나 같은 값을 60초 동안 보내지 않았을 때만 한다. 메시지 TTL은 150초다.
- 측정은 이 서버의 관측을 읽는 곳이 있으면 30초(±10%)마다, 없으면 5분마다 한다. 읽는 곳이 새로 생기면 바로 한 번 잰다.

## 노드 현황

Nodes의 각 행은 `{Node,State,Ready,Stale,Waiting?,ObservedAt,ObservationMaxAge,Usage?,Admin?}`다. `Waiting`은 그 서버가 이번 조회의 기다림(최대 2초) 안에 답하지 않았다는 뜻이고, 행은 그 전에 저장된 값이다(화면은 "대기 중"). `raft-status`의 Nodes 행에도 같은 `Waiting`이 있다. 상태는 unknown/pending/ready/unready 또는 현재 격리·복원·제거 단계다. `AdmitsWork`는 그 서버가 작업(앱·빌드)을 받는지다. 작업을 받지 않는 서버도 보고가 신선하고 맞추기가 성공하면 State는 ready이고, Ready만 false다. State가 unready면 `Reason?`이 고정 코드로 이유를 준다: `MODULE_PASS_FAILED`(맞추기 단계나 그 단계가 쓰는 사건 기록이 실패), `HOST_READ_FAILED`(호스트 CPU·메모리를 못 읽음), `UNKNOWN`(그 서버가 이유를 보내지 않는 이전 버전). 클러스터 관리자에게는 `FailedSteps?`(실패한 맞추기 단계 이름, 예 `node-storage`, `registries`, `event-log`)와 `FailingSince?`(실패가 이어진 시작 시각, Unix ms)도 준다. 오류 원문은 비밀이 섞일 수 있어 응답에 넣지 않고 그 서버의 sfcd 로그에만 남는다. 보고가 없거나 오래되면 Ready를 만들지 않는다. Ready와 `CanAcceptChanges`는 특정 앱의 배치·자원 예약·실행 허가가 아니다. `CanAcceptChanges`는 이번 조회가 fresh quorum 경로를 통과했는지를 나타내는 거친 상태다.

tenant 행은 자기 `Usage`만 포함한다. `{Tenant,Node,CPUUsed?,MemoryUsed?,Containers?,Problems?,ReservedCPU,ReservedMemory,QuotaCPU,QuotaMemory,QuotaRevision,ObservedAt,Stale,Complete}`를 반환한다. CPUUsed는 nanocores, 메모리는 바이트다. 예약량·한도는 현재 공유 정책에서 읽고 실제 사용량과 구분한다. Container/Problems는 앱 Task의 실제 owner 검사를 거친 수치다. 일부를 검사하지 못하면 Complete=false이며 확실한 전체 수량/사용량으로 표시하지 않는다.

system 행의 `Admin`은 주소·역할·버전, 호스트 CPU/메모리, 중복을 제거한 디스크 합계, 합의 관측과 그 시각/낡음 여부, tenant별 사용량 첫8행을 포함한다. `TenantsNext`는 같은 Node의 node-tenant-usage에 전달한다. tenant 응답에는 Admin·다른 tenant 수량·주소·역할·버전·서명 원문이 없다.

호스트 CPU는 `/proc/stat`의 두 관측 간 delta다. 첫 표본이나 counter reset은 unknown이다. 메모리는 MemTotal-MemAvailable을 사용한다. 컨테이너 CPU는 실제 Docker 표본과 이전 표본을 기존 stats 요약 코어로 계산한다. 사용량을 알 수 없으면 필드를 생략하며0으로 바꾸지 않는다. 종료가 확인된 컨테이너와 실제 빈 집합의0은 관측값이다. 끊긴 노드의 마지막 값은 시각과 Stale=true로 구분한다.

## 디스크

한 행은 같은 노드의 **파일시스템 하나**다. `{Node,ID,Mount,Device,Filesystem,State,Purposes,StorageRoots,SourceCount,Total?,Used?,Free?,Available?,InodesFree?,ObservedAt,ObservationMaxAge,Stale,MeasurementOnly}`를 반환한다.

대상은 `/`, Docker SDK가 알려 준 data-root, 클러스터에 등록된 node 저장 root뿐이다. 임의 경로나 모든 mount 목록을 요청할 수 없다. purpose는 system/container-runtime/storage-root다. 같은 파일시스템을 여러 경로에서 써도 하나로 합치며 ID는 node와 실제 FSID/type으로 만든다(FSID가 없으면 device/type). 후속 디스크 부족 이벤트도 이 ID를 사용한다. Used=Total-Free이며 Available은 일반 사용자가 사용할 수 있는 공간이다. 모두 관측값이고 quota 보장이 아니므로 MeasurementOnly=true다.

보고가 없으면 State=unknown·용량 필드 생략·Stale=true다. 이후 측정 실패는 성공했던 값을0으로 덮지 않는다. tenant 조회는 허용 root부터 고른 다음 중복을 제거한다. 시스템/런타임 경로와 device는 제외하고 허용 root의 등록 경로만 표시한다. 서로 다른 root의 stale 관측이 합쳐졌으면 그 사실도 Stale로 유지한다.

## 볼륨 사용량

`volumes` 행의 `UsedBytes?`·`UsageObservedAt?`는 Raft 상태가 아닌 소유 노드의 관측이다. 소유 노드는 관측 주기(30초)마다 자기가 소유한 수렴된 볼륨 중 **하나만** 잰다. 표본이 없는 볼륨을 먼저 재고, 없으면 5분이 지난 가장 오래된 표본을 다시 잰다. 나머지 표본은 새 envelope `At`으로 다시 서명해 보낸다. 측정은 `volume-usage`와 같은 제한 스캐너(항목 100,000·깊이 64·10초)와 단일 스캔 잠금을 쓴다. 잠금이 바쁘거나 한도를 넘거나 스캔이 끝나지 않으면 표본을 만들지 않는다.

보고 원천은 `volume/<Scope.Key()>`이고 payload는 `Volume:{Key,Binding,Entries,Files,Directories,LogicalBytes,AllocatedBytes,ScannedAt}`다. Binding은 그 볼륨의 NativeBinding(서명된 NativeReady digest)이다. 같은 볼륨의 더 오래된 ScannedAt은 저장된 새 표본을 덮지 않는다.

`volumes` 조회는 다음 조건을 모두 만족하는 표본만 행에 붙인다. UsedBytes는 AllocatedBytes이고 UsageObservedAt은 ScannedAt(Unix 밀리초)이다.

- 행의 Owner.Node가 보낸 표본이다.
- Key와 Binding이 행의 Key·NativeBinding과 같다.
- envelope가 fresh하다(120,000ms).
- ScannedAt이 30분(`VolumeUsageMaxAge`) 안이다.

그 밖에는 두 칸을 생략한다. 생략은 **모름**이며 0이 아니다. 이 값은 권한, quota, 백업 크기의 근거가 아니다.

## Mesh

Links 행은 `{ID,NodeA,NodeB,State,ObservedAt,ObservationMaxAge,Stale,Ends?}`다. ID는 정렬한 두 논리 node 이름의 `node-a/node-b` 형식이며 후속 tunnel-down 이벤트와 같은 식별자다. 투표 node를 포함한 현재 구성의 node 쌍과 가입 대기 쌍을 투영한다. pending은 가입 대기 또는 아직 연결 관측이 없다는 뜻이다.

관리자에게는 각 끝점의 `{ObservedBy,Observation,ObservedAt,Stale}`를 별도로 돌려준다. Observation은 `{ID,Peer,State,RTTMillis?,LossPct?,Measurement,LastHandshakeAt,LastChangeAt,Samples,Outages?,Dialer?,Via?}`다. Dialer는 그 쌍의 트래픽을 싣는 SFCP 세션을 연 쪽, Via는 그 세션이 다른 구성원의 경유 세션을 지날 때 그 구성원 이름이다. Via는 연결이 직접이면 비어 있고, 경유 세션이 생기는 0.1.1 전에는 늘 비어 있다. quic-go의 실제 SmoothedRTT와 PacketsLost/PacketsSent를 사용하며 Measurement=`quic-connection-cumulative`다. 연결이 바뀌면 카운터도 바뀐다. IP ping 결과나 일정 구간 패킷 손실 추정치로 꾸미지 않는다. RTT·송신 표본이 없으면 해당 값은 unknown이다.

양쪽이 다르면 down→degraded→up 순으로 나쁜 쪽을 대표 상태로 삼고 각 끝점을 유지한다. 한쪽만 있거나 표본이 오래됐으면 up으로 대표하지 않는다. Outages는 최근8개 실제 연결 단절 구간 `{StartedAt,EndedAt}`이며 종료 미관측은 EndedAt=0이다. tenant에는 자기 허용 node 사이의 대표 상태와 시각만 반환하고 RTT·손실·다른 쪽 상세는 반환하지 않는다.

## 합의 상태와 단절 시 조회

raft-status는 **연결한 노드에서 처리**하고 리더로 자동 전달하지 않는다. quorum barrier를 기다리지 않으며 로컬 마지막 적용 catalog/membership으로 현재 Session·관리자 권한을 검사한다. `LocalLastAppliedAuthorization:true`로 이 경계를 표시한다. 분할 중 다른 쪽에서 회수한 권한을 즉시 알 수 있다는 보장은 없으며 다른 관리 명령의 fresh quorum 정책을 대신하지 않는다.

응답에는 Leader,Term,CommitIndex,AppliedIndex,ConfigurationIndex,Voters,Quorum,RespondingVoters,ObservedBy,ObservedAt,ContactMaxAge,Stale,Local,Nodes,NodesNext,NodesRootRevision,Elections,ElectionEventsDropped,ObservationStorageError?,Ledger,Writes?,WritesSince?가 있다. configuration은 이미 내구 적용한 FSM 구성이다. 리더는 같은 term에서 최근 SDK heartbeat 한도 안에 받은 실제 ACK만 응답한 voter로 센다. follower는 같은 한도 안에 leader 연락을 받았을 때 자신과 그 leader만 센다(다른 follower는 세지 않는다). 그때 leader 행의 Role은 `leader`, 자신과 leader 행의 LastContact는 그 연락 시각이다. 과반을 확인하지 못하거나 follower에게 최근 leader 연락이 없으면 Stale=true다.

Nodes는32행씩이며 각 행은 `{Node,Role,Term,MatchIndex?,AppliedIndex?,SnapshotIndex?,LogBytes?,LogEntries?,LastContact,ObservedAt,Lag?,Stale,Version?,Features?}`다. Version은 그 서버의 마지막 보고에 실린 빌드 버전(`major.minor.build`, 응답한 서버 자신은 자기 버전)이고 모르면 없다. Features는 그 보고에 실린 기능 이름(major의 기본 기능만 쓰면 없음)이다. 리더는 성공한 AppendEntries의 정확한 prefix와 성공한 Snapshot ACK로 MatchIndex를 관측한다. follower의 LastLog를 일치한 prefix로 취급하지 않는다. AppliedIndex는 내구 FSM 위치에, 그 뒤로 상태를 바꾸지 않는 확정 항목(read barrier, leader no-op)을 더한 위치다. 다음 command·configuration 항목은 FSM이 내구 게시한 뒤에야 넘는다. 그래서 상태 변경이 없는 동안에도 CommitIndex를 따라간다. 다른 서버의 AppliedIndex는 그 서버가 보고한 값이다. follower는 자기 위치·역할과 leader 힌트를 중심으로 반환한다. cursor는 term/configuration·현재 catalog/membership·signed scope에 고정하고 변경 시 conflict다. ACK 카운터는 페이지마다 관측 시각을 가진다.

Local에는 SDK 역할·term·commit/last index, 내구 FSM 위치, snapshot index/bytes/time·주기·TrailingLogs, log first/last/count/bytes와 각 known flag가 있다. 재시작 직후 내구 applied 위치와 SDK의 live commit/last 위치가 아직 일치하는 prefix를 이루지 않으면 새 합의 표본은 사용 불가로 남긴다. live commit을 내구 applied 값으로 보정하지 않으며, host·disk 등 독립적인 정상 표본은 계속 게시한다. LogBytes는 Raft Bolt DB 파일 크기이며 stable metadata·할당 공간을 포함한다. 정확한 command payload 합계로 표시하지 않는다. snapshot 시각은 실제 파일 snapshot ID의 밀리초 시각이다.

Elections는 SDK의 role/leader 알림을 관측한 최근32건이다. `{Term,Leader,Role,StartedAt,ElectedAt,ObservedAt,Reason}`의 시각은 **알림 관측 시각**이고 전 클러스터의 원자적 선거 증명이 아니다. 비차단 observer의 누락 수와 관측 이력 저장 오류를 별도 표시한다. Ledger에는 epoch과 보존된 마지막 회전 시각·주체·원 request ID가 있다. Writes는 응답한 노드가 리더일 때만 있다. 그 term에 리더가 Raft 로그에 붙인 항목 수를 `{Kind,Count}`로 센 값으로, 많은 순서다. Kind는 명령 종류·상태 키의 고정 앞부분·기호 action(예: `report control/apps observe`, `change control/vault/… put-secret`, 첫 최신 읽기의 `read-barrier`)이다. 받아들여지지 않은 명령(거절·CAS 불일치)도 로그 항목이라 끝에 ` rejected`를 붙여 따로 센다. 작업 공간·앱·서버 이름이 든 키 뒷부분과 내용은 담지 않는다. 128종을 넘으면 `other`로 모은다. 리더 메모리 값이라 Raft에 저장하지 않고, 새 term에서 다시 센다. WritesSince는 센 시작 시각(Unix ms)이다. 과거 저장 형식에 없던 회전 metadata는 복원했다고 표시하지 않는다.

## CLI

```sh
sfcli --tenant shop node list
sfcli --tenant shop node disks node-a
sfcli --tenant shop cluster mesh
sfcli node list --all
sfcli node disks node-a --all
sfcli node tenants node-a
sfcli cluster status
```

CLI가 페이지를 이어 읽는다. 시스템 전체 조회는 `--all`을 명시한다. 명령 설명은 [sfcli node](../cli/node.md)와 [sfcli cluster](../cli/cluster.md)에 있다.

노드 측 원 관측은 Observation purpose kind1/2로 전달한다. signed `node-observation` record 하나는 host/disk/tenant usage/link/local consensus 중 하나만 담고 최대60KiB다. 현재 멤버의 TLS 신원과 record key/node를 대조해 observations.db에 저장한 뒤 ACK한다. 이 ACK는 로컬 관측 저장을 의미하며 관리 상태의 Raft 확정이나 실행 grant가 아니다.

host 표본의 `Features`는 그 서버 빌드의 기능 이름 목록이다(major별 기능 표, `internal/buildinfo/features.go`). 기본값(0.1.0)이면 비어 있다. 관리자 서버 요약(`node-summary`의 `Admin.Host.Features`)으로 읽는다. 클러스터 교집합은 모든 서버의 목록을 겹친 것이고, 오래된(Stale) 서버는 마지막 보고의 목록으로, 보고가 한 번도 없는 서버는 빈 목록으로 센다. sfcd 안의 `Transport.ClusterFeatures`와 같은 규칙이다.
