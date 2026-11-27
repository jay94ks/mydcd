# 노드의 미사용 이미지 캐시 정리

현재 RQ4 서버·CLI 연결 단계이며 마지막 실행 검증 전이다. 이 기능은 시스템 관리자가 선택한 노드의 Docker 이미지 캐시를 계획하고, 명시한 immutable image ID들만 삭제한다. 내장 registry의 manifest/blob이나 Volume·BuildKit 캐시를 삭제하지 않는다.

```sh
# 각 이미지의 실제 사용 수와 수락된 참조 수를 확인한다.
sfcli node images node-a
# 명시한 immutable ID만 삭제한다. 미리 보기와 기다리지 않기:
sfcli node images delete node-a sha256:FULL_64_HEX --dry-run
sfcli node images delete node-a sha256:FULL_64_HEX --no-wait
# 끊겼거나 --no-wait로 맡긴 작업은 작업 ID로 이어 본다.
sfcli op show ID
```

ID는 `sha256:`와64개 소문자 hex다. 이름·tag·축약 ID를 삭제 대상으로 받지 않는다. ID는 인자로 최대8개까지 명시하며 중복은 거부한다. 선택을 생략한 전체 prune이나 `--force`·하위 이미지 재귀 삭제 옵션은 제공하지 않는다. 상태의 `accepted`는 원 job 수락이며 SDK 삭제/디스크 공간 회수가 아니다.

## 권한과 사용 여부

계획/삭제에는 현재 시스템 관리자 `ManageCluster`와 credential의 `prune-node-images` 허용 범위가 필요하다. 현재 원 job 결과는 시스템 관리자가 조회한다. 일반 tenant 관리자는 노드 전체 캐시를 정리하지 못한다. 대상은 설치된 멤버 노드이며 다른 Docker 주소·임의 호스트 경로를 입력하지 않는다.

계획은 owner의 실제 Docker SDK `ImageList`·`ContainerList(All=true)`와 현재 quorum의 공유 참조를 사용한다. 이미지 summary의 `Containers=-1`을0으로 읽지 않는다. 정지 컨테이너와 다른 owner의 실제 컨테이너도 참조에 포함한다.

공유 참조는 해당 노드의 현재 Task source, 미제거 claim, 수락된 실행의 Task, 살아 있는 compiled lifecycle이 사용할 빌더 노드의 컴파일러 이미지와 미종결 compile job을 포함한다. 하나의 논리 key/정규화 참조는 중복 합산하지 않는다. 실행이 Closed여도 아직 미제거 claim이 있으면 그 참조를 유지한다. 모든 관련 참조를 읽지 못하면 미사용으로 처리하지 않는다.

각 Image의 `Containers==0 && References==0`이어야 삭제 가능한 미사용 이미지다. 목록에는 보호된 이미지도 그 수치와 함께 보일 수 있다. `Bytes`는 SDK가 보고한 이미지 크기이며 공유 layer를 고려한 실제 회수량이 아니다. 이미지 ID와 manifest digest는 다를 수 있으므로 원 ID와 정규화 RepoTags/RepoDigests 별칭을 함께 검사한다.

## 계획과 원 요청

계획은 owner 키로 서명한 최근 관측이다. 전체 목록 페이지는 별도 시점의 관측이며 여러 페이지를 하나의 고정 Docker snapshot이라고 취급하지 않는다. 삭제는 항상 명시 ID 목록을 새로 계획하고 최신 사용/참조와 원 선택을 검사한다. 계획 보존 기간은30초다.

원 job 수락 후에는 같은 노드의 pending 캐시 정리와 겹치는 새 정리 요청을 거부한다. 선택된 원 별칭은 pending 동안 새 app/CD·컴파일 배치 수락과 충돌하도록 검사한다. 미리보기/수락 뒤 이미지·컨테이너·참조가 바뀔 수 있으므로 owner가 각 SDK 호출 직전에 다시 검사한다. Docker 외부 운영자의 동시 변경까지 Seafield Cluster admission으로 직렬화한다고 표시하지 않는다. 최종 SDK는 `ImageRemove(Force=false,PruneChildren=false)`로 자체 사용 충돌도 검사한다.

CLI는 원 intent를 전송 전에 journal에 저장한다. 같은 request ID는 현재 존재 여부를 다시 계획하기 전에 원 서명·대상·결과를 사용한다. 원 요청의 node/ID 목록/action/operation이 달라지면 거부하며, 원 기록이 없는 `--resume-original`도 거부한다. 응답 유실을 새 operation ID나 새 선택으로 자동 대체하지 않는다.

## User API·포맷

Unix 소켓과 네트워크 SFCP의 기존 User purpose/frame·Session·서명 envelope를 사용한다. 다음은 추가 본문 예시이며 실제 client는 Nonce와 채널 challenge 서명을 포함한다. JSON 필드는 대문자로 시작하고 schema는1이다.

```json
{"Schema":1,"Method":"image-cache-plan","ImageCache":{"Node":"node-a","After":"","Operation":"","Images":["sha256:FULL_64_HEX"]}}
```

```json
{"Schema":1,"Method":"image-cache-status","ImageCache":{"Node":"","After":"","Operation":"cache-42"}}
```

`FULL_64_HEX`는 설명용 자리표시자다. 실제 입력에는 전체64자 hex를 넣는다. Request.Tenant/Node/After 등 바깥 selector는 비워 둔다. `ImageCache.After`는 전체 목록에서만 사용하고 명시 Images와 섞지 않는다.

| Method | Reply의 추가 필드 |
|---|---|
| image-cache-plan | ImageCachePlan |
| image-cache-status | ImageCacheStatus |
| whoami | `Data.Roots["control/image-cache"]`, `Data.ModuleEpoch` |
| 기존 operation/result | 원 사용자 요청의 Result/Found·공개 사유 |

| Plan 필드 | 내용 |
|---|---|
| Schema, Cluster, Node, Owner, Boot | 1, 클러스터·노드 ID/설치 키·관측 runtime 인증서 지문 |
| At, Index | UTC Unix 밀리초, owner가 확인한 공유 command prefix |
| Selection? | 명시한 전체 image ID들을 정렬한 목록. 생략은 읽기 목록이며 실행 선택 아님 |
| Images | 최대8개 Image |
| Next | 다음 목록의 After. 마지막 반환 이미지 ID이며 없으면 빈 문자열 |
| Signature | owner의 Ed25519 서명 |

Image는 `{ID,Aliases,Bytes,Containers,References}`다. Aliases는 정규화·정렬한 tag/manifest digest 목록이며 최대32개다. 계획 전체는24KiB 이내다. 예산을 넘는 선택은 더 작은 명시 목록으로 나누며 원 수락 job을 분할/초기화하지 않는다. 지원 예산을 넘는 native metadata는 명시 실패이며0개/미사용으로 꾸미지 않는다.

서명 domain은 `sfc-image-cache-plan-1` 뒤 NUL과 Signature를 null로 둔 JSON이다. `[32]byte`는 JSON 숫자 배열, 서명 바이트는 base64다. 실행은 기존 UserOperation의 `Change.Action=prune-node-images`, `Expected=0`, `Payload={Operation,Plan}`이다. 현재 ImageCacheRootRevision을 operation.RootRevision에 넣고 module epoch·원 request ID·선택 공개 Reason을 서명한다.

| Status 필드 | 내용 |
|---|---|
| Schema, Operation, User | 1, 원 operation ID·승인 사용자 ID |
| State | queued, running, done, failed |
| Revision, RootRevision, At | job CAS·공유 root revision·최근 진행 UTC Unix 초 |
| Plan | 원 서명 선택. 현재 사용량으로 덮어쓰지 않음 |
| Parts | 원 이미지 순서의 확인된 결과. 아직 없는 항목은 미정산 |
| Reason? | 원 공개 사유. Session/grant는 반환하지 않음 |

Part는 `{ID,State,Code,Error,At}`이며 At는 UTC Unix 밀리초다.

| Part.State | 의미 |
|---|---|
| removed | SDK 응답 성공 뒤 실제 image ID 부재 확인 |
| already-absent | 처음부터 없거나 응답 유실 뒤 실제 부재를 확인함. 원 SDK가 원인이었다고 단정하지 않음 |
| skipped | 현재 참조/별칭 변화나 Docker 사용 충돌로 삭제하지 않음 |
| failed | 현재 권한 회수·확정된 SDK 거부·삭제 미완료 등 |

하나의 항목이 실패/skip이어도 나머지 선택을 진행하며, 모두 정산된 뒤 하나라도 실패/skip이면 전체 State는 failed다. 통신 오류 뒤 실제 부재/확정된 거부를 모르면 해당 항목은 불명으로 유지하고 terminal 결과를 만들지 않는다. 실제 디스크 여유는 별도 `node disks` 관측으로 확인한다.

## 노드·저장·복구 경계

공유 job은 시스템 관리 자원 `control/image-cache`에 저장하고 queued/running을 node activity·원장 회수의 outstanding 참조로 포함한다. owner의 `maintenance/image-cache/`에는 원 선택 지문과 이미지별 sent/result를 동기 저장한다. 앱/tenant 종료가 이 기록이나 image selection을 삭제하지 않는다.

노드 Management method는 다음과 같다. Unix 사용자에게 이 노드 권한을 부여하지 않는다.

| Method | 입력/경계 |
|---|---|
| image-cache-native-plan | 현재 Session·원 target owner/최소 prefix·Query, native owner에서만 조회 |
| image-cache-plan-permit | owner의 Session/Query/후보 Images, 현재 quorum 권한과 공유 참조 수 |
| image-cache-work | 원 Operation, owner 전용 현재 grant·진행/참조와 prefix |
| image-cache-report | owner 서명 begin/item 보고, job/root/epoch CAS와 원 ID 순서 |

보고는 `{Schema,Cluster,Owner,Operation,Action,Expected,RootRevision,Epoch,At,Part?,Signature}`이며 domain은 `sfc-image-cache-report-1` 뒤 NUL과 Signature를 null로 둔 JSON이다. SDK 직전에는 현재 원 grant와 참조 수를 확인하고 private sent 저장 성공 후 호출한다. 저장 실패 시 SDK를 호출하지 않는다.

재개는 먼저 원 결과와 정확한 ID의 실제 부재를 확인한다. 원 결과가 불명이고 여전히 존재하면 현재 원 grant와 같은 ID로 멱등 캐시 정리를 이어갈 수 있다. 권한 회수 뒤에는 새 SDK 호출을 금지하며 관측 부재만으로 미실행/성공을 판정하지 않는다. 이전 sent가 불명이라면 후속 호출의 skip/거부만으로 그 이전 효과를 정산하지 않고 긍정적인 실제 부재를 확인할 때까지 원 fence/참조를 보존한다. 이 복구를 Task Stop/Start나 Volume writer 작업의 재전송 규칙으로 일반화하지 않는다.

공유 checkpoint는4MiB·최대128개 job이며 수락 전에 미정산 항목당4KiB를 예약한다. 실제 원 서명/계획 크기에 따라 더 일찍 예산 초과를 거부할 수 있다. 자동 무한 이력 보관·운영 캐시 전체 삭제를 약속하지 않는다.

외부 OCI에서 ticket으로 받은 이미지도 private 레시피의 실제 Process.ImageID로 보호한다. Desired·Applied·Unknown/Pending의 원 Target을 검사하고 metadata 해석 오류를 참조0으로 바꾸지 않는다. 앱의 레시피 resolve→Desired 게시와 실제 캐시 제거는 같은 node-local 배제로 직렬화한다. 준비한 native image ID(legacy config digest 또는 보존된 OCI manifest digest)는 현재 cache job fence를 확인한 뒤 게시하고 실제 Create의 이미지 허가에서도 검사한다. 원 삭제가 Unknown이면 새로운 레시피/재생성이 그 ID를 빌리지 않는다. 기존 실행 중 컨테이너의 상태 검사에 새 registry 자격을 요구하지 않으며 Docker alias/RepoDigest를 조작하거나 별도 origin DB를 추가하지 않는다.
