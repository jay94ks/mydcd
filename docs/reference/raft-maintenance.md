# Raft 수동 snapshot·로그 압축

RQ4 서버·CLI 연결은 마지막 실행 검증 전이다. UI는 이 API를 소비하며 별도 작업에서 구현한다. 수동 압축은 관리 변경을 중지하거나 원장 epoch를 교체하지 않고 각 노드의 기존 Raft SDK snapshot 기능을 실행한다.

```sh
# 기본: 설치된 voter 전체, 한 대씩, 현재 leader는 마지막
mydc cluster compact --dry-run
mydc cluster compact --minimal --retain 1000
# 대상을 명시하거나 follower 병렬 실행을 선택할 수 있다.
mydc cluster compact --nodes node-a,node-b --parallel --dry-run
# 끊긴 작업은 새로 계획하지 않고 같은 작업 ID로 이어 본다.
mydc op show ID
```

현재 시스템 관리자(`ManageCluster`)만 계획·실행·결과를 조회한다. 실행 credential의 동작 제한에는 `raft-compact`가 필요하다. tenant 관리자는 실행할 수 없다. 노드 키는 수락된 사용자 요청에 대한 현재 허가를 확인하고 자기 SDK 효과와 진행을 보고한다. 노드 보고가 새 사용자 승인을 만들지 않는다.

## 대상·보관량·진행

`keep`은 대상 노드의 현재 `TrailingLogs`를 유지한다. `minimal`은 실행 중에만 `min(현재 TrailingLogs, N)`을 사용하고 실제 SDK future 종료 후 원 값으로 복원한다. N은1부터2³⁰까지이며 CLI 기본값은1000이다. `--minimal` 없이 `--retain`을 지정할 수 없다. 다른 Raft 타이머와 설정을 덮어쓰지 않는다. 별도 설정 변경과 충돌하면 `restore-conflict`로 보고한다.

대상을 생략하면 설치된 voter를 계획에 고정한다. 진행 시 응답하지 않는 queued 노드는 `skipped/unreachable`로 남기므로 최종 실행 대상은 응답하는 voter다. `--nodes`는 설치된 노드 ID를 최대256개까지 명시한다. non-voter도 명시 대상으로 고를 수 있다. 주소·키를 임의 입력하거나 실행 중 바뀐 구성원을 원 요청에 자동 추가하지 않는다.

기본은 순차 실행이다. 실행할 때마다 실제 SDK leader를 확인해 현재 leader를 마지막에 둔다. `--parallel`도 leader는 나머지 대상이 terminal이 된 후 시작한다. 이미 실행 중인 노드가 leader가 됐다고 SDK 호출을 취소·재발행하지 않는다. 같은 노드의 queued/running 요청과 겹치는 새 요청은 거부한다. 한 대상의 실패는 나머지 대상 진행을 막지 않는다.

| State | 의미 |
|---|---|
| queued | Raft로 수락됐고 아직 SDK 실행을 시작하지 않음 |
| running | owner의 시작 보고가 확정됨. 실제 SDK 결과 정산이 필요함 |
| done | 수락 prefix snapshot·설정 복원·관측된 보관 목표를 모두 확인함 |
| failed | SDK/복원/보관 목표 실패 또는 실행 전 권한 회수. Code와 가능한 실제 결과를 보존함 |
| skipped | queued 대상이 응답하지 않아 leader가 서명 보고함. running을 이 상태로 바꾸지 않음 |

`compact`의 `status: accepted`는 공유 job의 수락이며 모든 노드의 완료가 아니다. 최종 결과는 `compact-status`에서 확인한다. snapshot 이후 새 tail이 보관 건수를 넘으면 `TargetMet=false`, `retention-not-met`로 남긴다. 새 tail을 지워 목표 수치를 맞추지 않는다.

## User 메시지와 포맷

Unix TLS와 네트워크 MYDCP의 기존 User purpose/frame/envelope·Session 인증을 사용한다. JSON 필드 이름은 아래와 같이 대문자로 시작하며 버전은1이다. `[32]byte`는 JSON 숫자 배열, `Signature` 바이트는 기존 base64 규칙을 따른다.

| Method | Request의 추가 필드 | Reply의 추가 필드 |
|---|---|---|
| raft-compact-plan | `Compact:{Selection:{Mode,Retain,Parallel,Nodes?},Operation:"",After:""}` | CompactPlan 페이지 |
| raft-compact-status | `Compact:{Operation,After:""}`; Selection 없음 | CompactStatus 페이지 |
| whoami | 기존 요청 | CompactRootRevision, ModuleEpoch |
| operation/result | 기존 UserOperation/원 request ID | 기존 Result/Found; SDK 완료와 구분 |
| raft-status | 기존 요청 | RaftStatus.LastManualCompact와 Nodes[].LastManualCompact |

위 요청에는 별도 Tenant/Node/바깥 After를 넣지 않는다. 모든 페이지 cursor는 `Compact.After`에 넣는다. 기존 Request의 Schema·Method·Nonce와 인증 envelope 필드는 그대로 필요하다.

```json
{"Schema":1,"Method":"raft-compact-plan","Compact":{"Selection":{"Mode":"minimal","Retain":1000,"Parallel":false},"Operation":"","After":""}}
```

이는 추가 필드를 설명하는 본문 예시이며 실제 전송은 기존 client가 Nonce와 서명 envelope를 붙인다.

| CompactPlan 페이지 필드 | 내용 |
|---|---|
| Schema, Cluster | 1, 현재 클러스터 ID |
| Selection, Target | 원 선택과 그 선택/노드 ID/키를 묶은32바이트 지문 |
| Total, Nodes, Next | 전체 대상 수, 최대64개 clean queued 행, 다음 opaque cursor |

client의 `CompactPlan`은 최대16페이지를 같은 Target/Total로 수집하고 전체 계획을 검증한다. roster가 달라진 cursor는 `conflict / COMPACT_VIEW_CHANGED`다. 미리보기가 실제 수락을 보장하지 않으며 수락 시 현재 권한·구성·겹친 작업·저장 예산을 다시 검사한다.

실행은 기존 서명 UserOperation을 사용한다.

| 필드 | 내용 |
|---|---|
| Change.Action | raft-compact |
| Change.Expected | 0: 새 원 operation ID만 허용 |
| Change.Payload | `{Operation,Selection:{Nodes?,Mode,Retain,Parallel},Target}` |
| RootRevision, Epoch | whoami의 CompactRootRevision을 원 operation.RootRevision에 넣고 현재 module epoch를 사용 |
| Reason | 선택한 공개 Text·IncidentID·ApprovedBy metadata. 승인 권한을 만들지 않음 |

CLI는 전송 전에 원 intent를 journal에 저장한다. 같은 request ID를 다시 실행하면 원 서명·계획·결과를 사용한다. 원 기록이 없거나 대상/선택이 다르면 명시 재개를 거부한다. 결과 불명으로 새 operation ID를 자동 발급하지 않는다.

| CompactStatus 페이지 필드 | 내용 |
|---|---|
| Schema, Cluster, RootRevision | 1, 클러스터 ID, 같은 조회의 maintenance root revision |
| Summary | Operation, User, At, AcceptedIndex, Options, Sequential, Complete, Total와 Queued/Running/Done/Failed/Skipped 수 |
| Target, Reason | 원 선택 지문과 공개 사유. Session·원 grant는 반환하지 않음 |
| Nodes | 최대4개 `{Node,Key,Revision,State,Code?,Result?}` |
| Next | 다음 페이지. root revision 변경 시 cursor 거부 후 첫 페이지부터 다시 조회 |

`At`은 UTC Unix 초의 해당 job 최근 진행 시각이며 노드별 완료 시각을 뜻하지 않는다. `AcceptedIndex`는 공유 상태의 command 순번이다. 아래 `MinimumIndex`는 실제 Raft log 위치로 서로 바꿔 쓰지 않는다.

| 노드 Result 필드 | 내용 |
|---|---|
| Schema, Dispatch | 1과 원 SDK 전송 기록 |
| Dispatch | Schema, Operation, At(노드 UTC Unix 나노초), MinimumIndex, Options, ConfiguredTrailing, EffectiveTrailing, Before |
| After | SDK 종료 후 metrics; 관측 실패는 Known=false |
| DurationMillis | 실제 로컬 SDK 작업 시간 |
| ConfigRestored, TargetMet | 보관 설정 복원과 prefix snapshot을 포함한 보관 목표 충족 여부 |
| ErrorCode, Error | 제한된 실패 코드·원인. 빈 값은 오류 없음 |
| FileReclamation | Bolt의 논리 회수·물리 파일 크기 차이에 대한 안내 |
| ObservedRecovery? | 원 결과 유실 후 동등한 실제 SDK 상태를 확인해 정산했는지 |

Before/After metrics는 `LogKnown,LogFileKnown,LogUsedKnown,SnapshotKnown`과 `FirstIndex,LastIndex,LogEntries,LogFileBytes,LogUsedBytes,LogFreeBytes,SnapshotIndex,SnapshotBytes`를 담는다. Known=false를0바이트 성공으로 읽지 않는다. LogUsedBytes는 파일 크기에서 Bolt FreeAlloc을 뺀 page 수준 추정이며 데이터 payload 크기와 다르다.

`raft-status`의 전역 LastManualCompact는 최신 job Summary다. 각 Nodes[].LastManualCompact는 해당 노드가 포함된 최신 job의 Operation/User/At/State/Code와 snapshot·로그 전후 수치·Known·DurationMillis·ConfigRestored·TargetMet을 요약한다. `raft-status`는 기존처럼 quorum 없는 로컬 진단이므로 stale 표시를 함께 읽는다. 권위 있는 원 job 진행 조회는 `raft-compact-status`의 quorum read를 사용한다.

## Owner 실행·복구와 저장 경계

노드 간 Management method `compact-work`는 `{Operation}`을 받아 원 owner·대상/키·상태/revision·현재 leader·공유 root/epoch/index·원 grant 허용 여부·실행 순서를 반환하는 quorum read다. `compact-report`는 owner/leader의 서명 보고 `{Schema,Cluster,Reporter,Operation,Node,Action,Leader,Expected,RootRevision,Epoch,At,Result?,Code?,Signature}`를 받는다. 서명 domain은 `mydc-raft-compact-report-1` 뒤 NUL과 Signature를 null로 둔 JSON이다. begin/finish/cancel은 owner, queued skip은 현재 leader만 보고한다. Unix 사용자 연결은 이 노드 권한을 얻지 않는다.

공유 job은 `control/raft-maintenance`에, SDK 호출 직전 Dispatch와 실제 terminal 결과는 owner private DB의 `maintenance/compact/`에 저장한다. 원 job은 미정산 node activity·원장 교체/종료의 outstanding 참조에 포함한다. 앱/tenant가 이 시스템 유지보수 자원을 소유하거나 앱 종료로 삭제하지 않는다.

private 전송 기록의 동기 저장이 실패하면 SDK 호출과 설정 변경을 하지 않는다. 실제 호출은 `hashicorp/raft.Snapshot()`이며 SDK가 snapshot Persist/Close를 마친 뒤 자기 로그를 삭제한다. caller 취소·응답 유실을 완료로 처리하지 않고 실제 future를 기다린 후 설정 복원·결과 저장·서명 진행 보고를 한다. daemon 종료도 추적한 작업을 기다린다.

재시작 시 원 기록과 실제 SDK snapshot 위치·보관량·설정을 대조한다. 긍정적인 동등 상태가 있으면 `ObservedRecovery`로 정산한다. 증거가 없고 원 승인도 회수됐으면 running을 임의 성공/skip으로 정산하지 않는다. 현재 원 승인이 유효한 경우 같은 operation의 멱등적인 SDK snapshot/retention 작업을 이어갈 수 있다. 새 job·새 사용자 승인으로 바꾸거나 Task Stop/Start 재전송 규칙에 일반화하지 않는다.

job은 최대128개, 기본 roster는 최대1024개, 개별 결과는8KiB, checkpoint는4MiB다. 수락 전에 pending 대상당9KiB의 결과 공간을 예약하므로 큰 배치는 더 일찍 거부될 수 있다. 거부된 배치는 대상별 작은 명시 계획으로 나눌 수 있으나 수락된 원 작업을 분할/초기화하지 않는다. 완료 이력 자동 무한 보관이나 물리 파일 vacuum을 제공한다고 표시하지 않는다.

Bolt 로그를 삭제해도 할당된 파일은 바로 작아지지 않으며 free page가 후속 쓰기에 재사용된다. 이 기능은 파일을 복사·교체·vacuum하지 않는다. 물리 축소는 별도 offline 유지보수 절차가 필요한 작업이며 `mydcd` 재시작만으로 축소된다고 안내하지 않는다.
