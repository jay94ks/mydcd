# Task 관측 조회

`tasks`는 수락된 앱의 Task와 그 소유 노드가 서명한 관측을 읽는다. 조회가 컨테이너를 시작·종료하거나 Secret을 가져오지는 않는다.

## 요청과 페이지

SFCP User kind1의 Request는 다음 필드를 사용한다. 인증·record·서명은 [Unix API](unix-sockets.md)의 사용자 조회와 같다. 네트워크 SFCP에서도 같은 메시지를 쓴다.

```json
{"Schema":1,"Method":"tasks","Params":{"Node":"node-a","Tenant":"shop","App":"store"}}
```

`tasks`는 [typed method](unix-sockets/10-user.md#typed-method)다. `Params`의 `Node`, `Tenant`, `App`은 선택 필터이고(빈 문자열도 그대로 보낸다), `Standalone`(App과 함께 쓰지 않음)·`After`는 비면 뺀다. tenant를 생략하면 현재 사용자가 읽을 수 있는 tenant만 모은다. `TargetUser` 등 다른 method의 선택자는 허용하지 않는다. 현재 계정·서명된 Read scope·tenant membership·허용 node를 먼저 검사한 다음 정렬하고 페이지를 만든다. system admin도 Session의 Read scope가 있어야 한다. 일반 사용자가 Node만 지정해도 다른 tenant의 Task 수나 페이지 위치는 노출하지 않는다.

성공 응답의 `Data`는 `{Tasks,Next,RootRevision}`이다. 한 페이지는 최대16행, 행 JSON 합계96KiB다. Task key→generation→revision 순으로 정렬한다. cursor는 현재 상태 index·Apps/Catalog/Members/Vault root·사용자·서명 scope·전체 필터에 결합된다. 상태가 바뀌면 `conflict`로 거부하므로 빈 cursor에서 다시 시작하고 이전 페이지와 섞지 않는다. 총 Task 개수나 숨긴 행의 위치는 반환하지 않는다.

## Task 행

| 필드 | 형식·의미 |
|---|---|
| `Tenant`, `App`, `Deployment`, `Service`, `Node` | string: 수락된 앱·서비스·담당 노드 |
| `TaskID` | string: `container-observe`와 interactive exec의 `Selection.Instance`에 쓰는 동일 논리 Task key |
| `Generation`, `Revision` | uint64: 원 Task 객체의 세대·revision |
| `Container`, `ContainerName` | string: 관측한 실제 Docker ID·이름. 아직 보고되지 않았으면 빈 문자열 |
| `Image` | string: 수락된 서비스의 이미지 참조. digest로 고정한 입력은 그 digest를 유지 |
| `ImageID` | optional string: 소유자 Docker 검사에서 얻은 고정 이미지 ID. 원 `Image` 참조를 덮어쓰지 않음 |
| `Desired` | `running` 또는 `stopped`: 현재 목표·drain·앱 종료·세대 교체를 반영 |
| `Observed` | `running`, `exited`, `restarting`, `missing`, `unknown`: 소유자 관측. 목표 상태와 별개 |
| `StartedAt` | 선택 RFC3339Nano string: 실제 컨테이너 instance 시작 시각 |
| `RestartCount` | 선택 uint64: 신선한 Docker 관측의 재시작 횟수. 모르는 값은 생략 |
| `ExitCode` | 선택 int64: 보고된 실제 종료 코드 |
| `LastCheck` | 선택 `{Checker:string,Status:pass/fail/unknown,At:uint64}`: 현재 연결은 Docker healthcheck의 마지막 실제 결과 |
| `ObservedAt`, `ObservationMaxAge` | uint64 Unix초·최대 신선도 초. 현재 최대 신선도30초 |
| `Resources` | `{Kind,Name,Realm?,Borrowed}` 목록. 관리 network의 실제 이름·Volume·Secret/Secret Group의 논리 참조 |

관측이 없거나 미래 시각·신선도 초과이면 `Observed:unknown`이다. 이전 `ObservedAt`과 instance·종료 증거는 구분하여 남기고, 현재 재시작 수·검사 결과로 제시하지 않는다. 수락 후 아직 Claim을 수집하지 않은 Task도 `unknown`으로 보인다. 이전 세대의 network 참조는 새 세대가 같은 alias를 써도 원 이름을 유지한다.

설정 변경에서 Task를 `Keep`으로 재사용하면 원 효과의 claim·작업 ID·native는 보존한다. Task 조회·replica health·DNS 가용성은 동일 객체와 native에 대한 현재 실행의 검증된 서명 관측을 사용한다. 이전 작업의 관측 만료가 현재 관측을 가리지는 않으며, 현재 관측 자체의 만료나 노드 격리는 계속 적용한다.

실시간 상태는 정확한 원 컨테이너를 검사한 소유자가 서명한 task 측정에서 읽는다. 기존 lifecycle Observation의 공개 `TaskFact`는 원 실행의 마지막 증거로 재사용할 수 있다. task 측정은 기존 node-private observations DB와 SFCP Observation 경로를 사용하며 현재 member/원 Task key·generation·revision·native를 대조한다. 설치 키 교체 뒤에도 원 Task/native 사실은 유지하고, 새 측정 봉투만 현재 논리 노드 키로 서명해 현재 observations DB에 저장한다. 과거 DB의 기존 서명 보고를 다시 쓰거나 폐기 키의 외부 보고를 허용하지 않는다. 소유자 로컬 저장은 즉시, 다른 node 전달은 기존30초 보고 주기다. 조회 cursor는 현재 권한으로 거른 측정 행도 고정하므로 값이 바뀐 페이지를 섞을 수 없다. 외부 Docker 재시작의 새 process 시각이 보이더라도 원 제어 Start/Exit 증거·종료·Gone·Volume fence·관리 승인을 바꾸지 않는다. 이름만 사라졌다는 사실이나 Docker 조회 실패를 실제 native 종료 증거로 취급하지 않는다. Resource에는 환경 변수·provider 경로·credential·가져온 Secret 값·서명 원문을 넣지 않는다.

## CLI

```sh
sfcli --tenant shop manage tasks
sfcli --tenant shop manage tasks --app store --node node-a
sfcli manage tasks --all-tenants --node node-a
sfcli --tenant shop manage tasks --after '<Next>'
```

기본은 CLI에서 선택한 tenant다. `--all-tenants`도 현재 권한을 확대하지 않는다. 로그·통계·프로세스·exec는 반환된 TaskID를 사용하여 [컨테이너 운영 API](container-operations.md)를 호출한다.


다중 배치에서는 논리 Service와 exact TaskID/세대/노드를 함께 표시한다. 순차 갱신의 held 관측은 원 native의 증거이며 새 target의 Applied/성공이 아니다. 일부만 현재 가용한 replica 그룹은 앱 Health가 `Degraded`이고, 이전 operation의 `Succeeded`는 유지한다. 사용자 앱 조회는 현재 WorkKey·원 Task/native·세대/리비전·fresh health도 대조한다. DNS 응답 제외는 원 Task/주소/Secret/Volume 참조의 삭제나 native 종료 증명이 아니다.
