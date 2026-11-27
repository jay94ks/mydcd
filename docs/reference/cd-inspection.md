# CD 후보 이력·설정값·변경점 조회

## 별도 로컬 서비스 추가분

Git 원문은 그대로 두고 별도 YAML의 새 서비스와 공유 자원 이름 참조만 미래 후보에 병합한다. 같은 이름의 Git 서비스나 서로 다른 별칭 정의는 충돌이며, 로컬 서비스가 Git 서비스에 시작 의존을 거는 것도 거부한다. 로컬 서비스끼리의 의존은 허용한다.

```sh
sfcli --tenant shop cd put-local website --file local.yaml --request-id local-edit-1
sfcli --tenant shop cd clear-local website --request-id local-clear-1 --local-revision 1
sfcli --tenant shop cd sync website --request-id sync-2 --operation rollout-2
```

`put-local`은 추가분 전체 교체이고 `clear-local`은 추가분 전체 제거다. 두 명령 자체는 실행 중인 컨테이너를 바꾸지 않는다. clear 후 후보에서 빠진 서비스의 실제 종료에는 `sync.prune: true`가 필요하다. prune이 꺼져 있으면 기존 orphan claim/native를 보존한다. 실제 적용·종료·참조 반환은 기존 명시/정책상 CD sync가 수행한다. Git fetch/prune가 별도 추가분을 임의로 삭제하지 않는다. Git에 같은 서비스가 들어오면 기존 실행/추가분을 보존하고 새 sync를 멈춘다.

앱 조회의 `CD.LocalRevision`, `LocalTarget`, `LocalActor`, `LocalServices`가 편집 기준이다. 기본은 signed `Target`과 정확한 이전 local revision CAS이며 `--expected-revision N`은 기존 strict CD/root CAS를 선택한다. `--local-revision N`으로 이전 local revision도 명시 확인할 수 있다. 무관한 업로드/health 보고가 원 편집 의도를 바꾸지 않으며, 다른 local 편집·source/정책/실행 변경은 원 Target을 무효화한다.

put은 기존 소유자별 app-upload를 사용한다. 서버가 완료된 원 바이트의 digest·서비스 이름·tenant/app/deployment를 다시 확인하고 후보와 작성자 서명을 함께 저장한 뒤 업로드를 소비한다. 업로드 중 끊기면 같은 `--file`·`--request-id`와 `--resume-original`로 원 조각 요청을 이어간다. 최종 편집 요청이 이미 journal에 있으면 `--file`을 생략하고 원 결과/요청만 조회·재개한다. 소비됐을 수 있는 업로드를 자동 재생성하지 않는다. clear도 원 서명 요청을 보존한다.

작성자는 현재 Deploy와 대상 노드/이미지·망·lifecycle·Volume/Secret 권한을 가져야 한다. 원 CD 등록 grant와 Group 승인 requester는 그대로이며 작성자의 권한을 대신하지 않는다. 새 효과와 Binding/Secret 공급에서 수락 당시의 별도 작성자 grant를 현재 권한으로 다시 검사한다. 후보 편집/clear 뒤에도 과거 실행의 grant는 고정 보존한다. 로컬 편집 자체에 ManageCD는 요구하지 않지만 실제 sync에는 기존 CD 권한·원 등록 grant·Group 승인이 필요하다.

`manage app-source --section local-services`는 보존 실행 버전의 별도 원문을 읽는다. 후보 이력의 optional `LocalRevision`, `LocalActor`는 로컬 편집을 구분하는 공개 metadata이며 별도의 실행 성공 증명이 아니다. Git 원문·현재 수락 버전·추가분을 하나의 원문으로 덮어쓰지 않는다.

CD 조회는 선택 tenant의 앱 Read 권한으로 같은 사용자 SFCP API를 호출한다. Unix `/run/sfcdp.sock`과 네트워크 연결에서 Session·challenge 서명·현재 권한·quorum/leader forwarding을 동일하게 적용한다. UI와 CLI가 서로 다른 관리 상태나 실행 권한을 갖지 않는다. 구현 수락 근거는 HISTORY에서 관리한다.

```sh
sfcli --cluster production --tenant shop cd history website
sfcli --tenant shop cd history website --after '이전 응답 Next'
sfcli --tenant shop cd field website --field services/web/image
sfcli --tenant shop cd diff website
```

이 명령은 request ID·expected revision·resume·관리 사유를 받지 않는 조회다. source 조회·이력의 성공은 후보 실행이나 컨테이너 health 성공이 아니다.

## 후보와 실행 이력

User kind1 method는 `app-cd-history`다. 공통 `Schema:1,Nonce`와 `Tenant`, `AppCDRead:{App}`를 보내고 후속 페이지에서 바깥 `After`에 이전 `Next`를 넣는다. Node/App·다른 method payload·Secret·operation을 함께 넣으면 거부한다. 응답은 `Reply{Schema:1,Code:"ok",AppCDHistory:Page}`다.

| Page 필드 | 의미 |
|---|---|
| `Schema`, `Tenant`, `App` | 1과 원 선택 |
| `Records` | 최신 순, 최대16행 |
| `Next` | 다음 페이지의 opaque After. 현재 history와 현재 권한 기반에 고정 |
| `First`, `Last` | 보존된 첫 순번과 마지막 발급 순번 |
| `Truncated` | 오래된 조회 metadata가 유한 보존 한도에서 회수됐음 |

행은 `Sequence`, `Identity`, `Candidate`, `LatestCandidate`, `Artifact`, `Intent`, `Commit`, `Operation`, `Status`, `Code`, `Actor`, `Reason`, `PlannedAt`, `CompletedAt`을 가진다. digest는 공통 고정32 byte array, 시각은 Unix seconds다. 과거 입력의 정확한 계획 시각을 확보하지 못한 경우 PlannedAt은0이다. 현재 시각을 과거 계획 시각으로 만들어 넣지 않는다.

`Identity`는 source artifact/commit과 실행 의도에 고정한 이력 식별자다. `Candidate`는 최초 관측한 후보의 계획 지문, `LatestCandidate`는 같은 의도의 최신 CAS 계획 지문이다. health·fetch poll만으로 새 이력 행이나 새 배포 성공을 만들지 않는다. 원 후보가 실행되면 같은 행에 원 operation과 실제 Inventory 결과/완료 시각을 연결한다. 같은 의도를 새 명시 operation으로 실행하면 별도 행으로 보존한다.

Status는 `candidate`, `executing`, `succeeded`, `failed`, `discarded`, `blocked`다. superseded 후보와 거부/source 오류의 공개 Code를 구분하며 provider 오류 원문은 보존하지 않는다. Actor/Reason은 원 사용자 후보 결정의 서명된 표시 metadata이며 권한 증거가 아니다. 이력은 앱의 같은 Raft checkpoint에 최대128행을 보존한다. 회수되는 것은 조회 metadata이며 원 작업·미정산 실행·source/Volume/Secret pin의 수명은 기존 Inventory/이력 회수 계약을 따른다.

조회 중 이력/권한 기반이 달라지면 원 After를 거부한다. client는 자동으로 첫 페이지로 돌아가 누락을 숨기지 않는다. 현재 권한 회수·다른 tenant 선택에는 기존 거부를 적용한다.

## Git 값과 현재 의도 값

기존 `app-cd-field` 요청의 `AppCDField:{App,Path}`를 사용한다. 응답의 field 소유 revision·Target·원 Task refs/anchor는 그대로 유지한다. `Values`는 다음 정보를 덧붙인다.

| 필드 | 의미 |
|---|---|
| `SourceCommit`, `Source` | 최신 후보의 원 source commit과 원 field 값 |
| `CurrentCommit`, `RunningSource` | 수락된 실행의 원 source commit과 원 field 값 |
| `Current` | 현재 수락된 실행의 선언 값 또는 명시 override 값 |
| `Overridden` | 이 field에 명시 override가 있음 |
| `CurrentOrigin` | `accepted-execution`, `override-intent`, 실행 선택 전의 `candidate-intent` |

각 값은 `{Present:bool,Value?:JSON}`다. 없는 field와 명시 JSON null을 구분한다. override는 수락된 의도 값이며 실제 적용/health는 원 refs와 앱 operation/관측으로 따로 확인한다. 새 Git 후보의 값을 이미 실행된 값으로 보여 주지 않는다.

값은 허용된 service field와 app 선언에서만 얻는다. Secret backend·projection·이미지 기본 env·native inspect에서 값을 해제하지 않는다. Secret은 원 선언의 이름/키 참조로 남는다. node/관리 망/Volume/Secret 정책을 field 조회나 override 권한으로 확대하지 않는다.

값 JSON이24KiB를 넘으면 `Values` 대신 `ValuesPart`를 반환한다. 후속 `AppCDField.Part`와 `Digest`로 같은 snapshot을 모은다. SDK의 `AppDeliveryField`와 CLI는 전체 part/길이/digest를 확인하여 `Values`로 조립한다. 다른 snapshot의 값이나 현재 권한으로 자동 fallback하지 않는다.

## 서비스 field 변경점

method는 `app-cd-diff`, 입력은 `Tenant,AppCDRead:{App,Part:0,Digest:[32]byte}`다. 후속 part는 반환된 Digest를 넣고 Part를 증가시킨다. 바깥 After는 받지 않는다. 응답의 `AppCDSnapshot`은 아래 분할 형식이다. SDK `AppDeliveryDiff`와 CLI는 조립된 다음 객체를 반환한다.

`{Schema:1,Tenant,App,Candidate,Running?,Changes:[{Service,Action,Path,Before,After}],ChangeCount}`. Candidate/Running은 원 DeliverySelection이다. Action은 `added`, `removed`, `changed`다. 추가/제거 서비스는 `Path:["services",NAME]`의 구조 행이고 전체 선언은 기존 원문 API로 읽는다. changed는 field 경로와 이전/이후 `PublicFieldValue`를 제공한다. map은 field별로 비교하고 array/scalar는 하나의 field 값으로 비교한다. 순서는 서비스 이름과 field 경로 순으로 결정한다.

`ChangeCount`와 `cd status`의 `CD.ChangeCount`는 같은 Changes 길이다. Git의 이미지 한 줄만 바뀌었다면 해당 서비스의 image 경로 한 행이다. resource CAS/health sequence·하위 inputs 재생성 개수를 이 개수에 합치지 않는다.

Diff의 optional `Replacement`는 현재 원 claim과 후보의 노드별 교체 영향 계획이다. `Required`, 선택 `BlockedCode`/`Blocker`, `Waves:[{Node,Tasks,Targets}]`를 제공한다. Targets는 exact Key/Revision/Generation이며 새 native나 종료 증명이 아니다. 다른 노드 Task를 함께 종료하는 수명 의존은 `ROLLING_DEPENDENCY_CONFLICT`, 미정산 원 작업은 `ORIGINAL_OPERATION_PENDING`이다. 파동 실행·실제 health 조건의 수락은 별도이며, field Changes/ChangeCount와 종료 대상 수를 합산하지 않는다.

| 분할 필드 | 규칙 |
|---|---|
| `Schema`, `Tenant`, `App`, `Kind` | 1과 원 선택, Kind는 `diff` 또는 `field-values` |
| `Part`, `Length` | 0부터의 part와 전체 JSON byte 길이, 최대16MiB |
| `Digest` | 전체 JSON의 SHA-256, 고정32 byte array |
| `Data` | 최대24KiB의 JSON 조각, Go JSON byte slice의 base64 |

모든 part는 같은 길이·digest·선택자여야 한다. source/현재 값이 달라져 원 digest와 맞지 않으면 conflict이며, 권한을 매 요청 재검사한다. 원 snapshot을 다른 후보로 이어 붙이거나 완전하지 않은 부분을 전체 값으로 출력하지 않는다. 별도 조회 서버·비인증 RPC·관리 변경은 만들지 않는다.

다중 배치 서비스의 field 변경은 한 임의 Task를 선택하지 않고 해당 서비스의 모든 instance anchor에 고정한다(최대128). 각 anchor의 현재 Task/Binding과 대상 field 의도 CAS를 확인한다. 같은 노드의 여러 ordinal도 별도 anchor이며 현재 health 보고만으로 field target을 바꾸지 않는다.
