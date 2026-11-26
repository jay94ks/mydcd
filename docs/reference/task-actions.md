# Task 하나 재시작

현재 RQ4 구현을 연결 중이며 마지막 통합 검증 전이다. UI는 이 문서의 서버·CLI 계약을 소비하며 별도 작업에서 구현한다.

```sh
mydc --tenant team-a app restart shop web
mydc --tenant team-a --reason '응답 중단' \
  app restart shop web -y --id restart-web-42
mydc --tenant team-a op show restart-web-42
```

선택자는 앱·서비스 이름이다. 해당 서비스에 후보가 여러 개면 `--instance TASK_KEY`로 논리 Task를 지정한다. Docker ID나 새 노드를 입력해 임의 컨테이너로 바꿀 수 없다. `restart`는 대상을 보여 주고 확인을 묻는다(스크립트는 `-y`). 앱 배포/복제 수/이미지/목표 세대를 변경하지 않고 원 컨테이너를 Stop한 뒤 Start한다. 원 Docker ID·writable layer·로컬 로그·Volume과 망 참조를 보존한다. 컨테이너 프로세스의 메모리 상태는 보존하지 않는다.

## 미리보기와 수락

`task-restart-plan`은 `Request.TaskRestart.Selection={App,Service,Instance}`와 `Tenant`를 받는다. 현재 사용자에게 tenant `Read`와 해당 노드 `Deploy`가 있어야 한다. credential에 `Operations`가 있으면 `restart-task`도 포함되어야 한다. 원 앱이 종료/이관 중이거나 같은 Task의 미정산 재시작이 있으면 새 요청을 받지 않는다. 원 native·실행 시각이 있는 최근 30초 이내 서명 관측과 기존 Binding을 사용한다.

`Reply.TaskRestartPlan`의 형식은 다음과 같다. `[32]byte`는 기존 MYDCP JSON 규칙인 32개 byte 배열이다.

| 필드 | 의미 |
|---|---|
| Schema | 1 |
| Tenant, App | 대상 tenant와 앱 |
| InventoryRevision | 읽은 앱 inventory revision |
| Registration | 원 앱 등록의 지문 |
| Target | 원 등록·Task·native·실행 시각·정지 정책을 묶은 지문 |
| Container | Cluster/Owner/Binding, Tenant/App/Service/Node/Instance, Generation/Revision, NativeID/StartedAt |
| OwnerBoot | 원 관측의 owner boot 지문 |
| StopGraceSeconds | 앱 정지 유예, 미지정 시 10초 |
| PreserveNative, PreserveWritableLayer, PreserveLogs | 모두 true |

실행은 기존 서명 `UserOperation.Change`의 `Action="restart-task"`, `Expected=InventoryRevision`, `Payload={Tenant,App,Operation,Selection:{Service,Instance},Target}`로 수락한다. 원 operation의 `RootRevision`은 Apps root를 가리킨다. Task 대상 지문이 같으면 다른 health 보고로 inventory가 증가한 것만으로 거부하지 않는다. 실제 native/실행 시각·앱 등록·원 참조가 바뀌면 같은 지문으로 실행할 수 없다.

CLI는 새 계획을 얻기 전에 로컬 원 operation journal을 확인한다. 같은 ID를 다시 실행하면 원 서명·대상·결과를 사용한다. 새 실행 시각에 맞춘 자동 재계획/새 ID 발급은 하지 않는다. 수락은 실제 재시작 완료를 뜻하지 않는다.

## 실행과 복구

담당 노드가 기존 Docker SDK·ContainerControl·Volume StartExisting 경계를 사용한다. `prepared → stop-sent → stopped → start-sent → completed`이며 대상 교체/권한 회수 등으로 새 호출을 할 수 없으면 `canceled`로 정산한다. SDK 호출 직전에 private DB에 sent 단계를 동기 저장한다. 전송 후 단절되면 그 원 native의 실제 상태를 확인하며 같은 Stop/Start를 다시 전송하지 않는다. 관측이 부족하면 sent 상태가 계속 남는다.

새 SDK 호출마다 현재 quorum과 수락 grant의 현재 계정·credential·tenant/노드 권한 및 `restart-task` 제한을 다시 검사한다. 원 앱의 Secret/Volume/배치 권한 검사도 유지한다. 새 호출이 금지되어도 이미 보낸 호출의 실제 결과 관측과 원 기록의 정산은 유지한다. 진행 중 checker 실행/제어를 먼저 정산하고, 재시작 중 새 checker 호출은 보류한다. 가짜 health pass/fail을 만들어 명시 요청을 실행하지 않는다.

노드가 서명한 `task-restart-report`는 원 수락 행의 진행만 갱신한다. 완료 보고가 Raft에 반영된 다음에만 `Observation.Restart.User={Operation,Request}`와 원 `Control`을 사용해 새 실행 시각의 제어 증거를 게시한다. 이것은 일반 외부 restart의 읽기 전용 측정을 제어 승인으로 바꾸지 않는다. 보고 응답이 유실되면 private 원 기록의 결과를 먼저 정산한 뒤 새 실행 관측을 게시한다.

## 원 결과 조회

`task-restart-status`는 `Tenant`, `TaskRestart={Selection:{App},Operation}`을 받는다. 현재 tenant `Read`가 필요하며 서비스/instance를 다시 선택하지 않는다. `Reply.TaskRestartStatus`는 다음을 포함한다.

| 필드 | 의미 |
|---|---|
| Operation, Status | 원 ID와 Accepted/prepared/stop-sent/stopped/start-sent/completed/canceled |
| User, Reason | 원 계정 ID와 선택 사유/사건/승인 표시 metadata. 표시 자체는 승인 증거가 아님 |
| Plan | 원 미리보기의 고정 대상 |
| Revision, At | 해당 진행 행의 revision과 마지막 보고 UTC Unix 초 |
| Control | 실행 전 생략 가능. Schema/RunID/RequestDigest/Target/Action/Phase |

원 승인/진행은 기존 Apps 저장소에, SDK 전송 단계는 원 owner의 private DB에 보관한다. 앱당 최대128개 원 행을 보존하며 한도가 차면 새 요청을 거부하고 미정산 원 기록을 덮지 않는다. 결과 조회는 노드 키만으로 새 작업을 발행하는 기능이 아니다. 관리 Unix 소켓과 네트워크 MYDCP User 요청은 같은 사용자 승인 코어를 쓴다.

## 노드의 새 배치 제외·복원

```sh
mydc node cordon node-a '디스크 교체'
mydc node uncordon node-a
mydc node show node-a
```

`cordon-node`/`uncordon-node`는 시스템 관리자의 사용자 서명 operation이다. credential 동작 제한이 있으면 해당 이름도 포함되어야 한다. payload는 `{ID:node-id}`이고 `cordon-node`는 선택 `Reason`(256자 이하, 줄바꿈·NUL 없음)을 더 받는다(`control.NodeCordonChange`). Reason은 서명된 원 operation에만 남고 `members`의 `NodeLifecycle[].Scheduling.Reason`으로 보인다. `Change.Expected`는 해당 노드의 **scheduling revision**이다. 미등록 scheduling 상태는 revision0/Enabled=false이며, 상태 변경마다 scheduling revision만 증가한다. join entry revision이나 node lifecycle revision/epoch와 혼동하지 않는다. 원 operation root는 Members root다. CLI는 현재 quorum에서 scheduling revision을 읽어 보내며 `--if-revision`으로 고정할 수 있다. 이미 같은 상태면 아무것도 보내지 않는다.

상태는 기존 membership Directory 안의 별도 scheduling metadata로 보관하며 public `NodeLifecycle[].Scheduling={Enabled,Revision}`에 표시한다. 기존 `AdmitsWork`는 이미 맡은 업무를 계속할 수 있는 권한이며 scheduling 허용과 구분한다. 새 app 계획·수락·CD 재계획·이관 대상 선택은 cordoned 노드를 배치 불가로 본다. 이미 수락된 Task/Binding과 그 Secret·Volume·정산·명시 재시작 권한은 이 플래그로 회수하지 않는다. 기존 컨테이너를 중지·재배포하지 않으며 Raft voter·installed key·MYDCP 접속을 변경하지 않는다. 실제 격리/제거는 별도의 기존 node lifecycle 명령이다.

`uncordon`은 이 scheduling 제외만 해제한다. 이미 격리/제거된 노드를 복구하거나 업무 권한을 추가하지 않는다. 실행은 기존 원 operation journal/결과를 보존하며 `--resume-original`은 같은 원 요청의 명시 재개만 허용한다. 새 플래그 변경을 하려면 현재 scheduling revision과 새 요청 ID를 사용한다.

미정산 재시작은 기존 앱/원장 회수와 노드·tenant 종료의 outstanding activity에 포함한다. Task가 제거됐다는 이유만으로 sent 요청을 정산하거나 원 owner를 종료 완료로 처리하지 않는다. 같은 원 native의 부재/종료를 확인하고 진행을 terminal로 반영한 뒤 기존 종료·회수 경계를 통과한다.
