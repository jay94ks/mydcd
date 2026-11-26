# Registry 이미지 삭제·GC

현재 tenant의 내장 registry 또는 승인된 외부 source의 이미지를 명시적으로 정리한다. GC는 내장 registry만 대상으로 한다. 삭제·GC 계획과 실행은 `ManageRegistry`, 결과·공개 요약 조회는 `Read` 또는 `ManageRegistry`가 필요하다. 사용자 credential의 허용 동작 목록도 각각 `delete-registry-image`·`gc-registry`를 허용해야 한다. 외부 이미지는 `--external`을 명시한다. source 정의 자체의 삭제와 이미지 삭제를 구분하며 조건별 일괄 정리는 별도 경로다.

이 경로는 RQ6 마지막 검증 전이다. 아래 형식은 현재 구현 계약이며 실제 연동 완료 근거는 HISTORY와 남은 마일스톤에서 구분한다.

```sh
mydc --tenant payments image list private team/app
mydc --tenant payments image delete private team/app:stable --dry-run
mydc --tenant payments image delete private team/app:stable --id image-delete-42
mydc op show image-delete-42

mydc --tenant payments registry gc private --id image-gc-43
```

`image delete`의 두 번째 인자는 `REPOSITORY:TAG` 또는 `REPOSITORY@DIGEST`다. CLI는 먼저 목록에서 지금 digest를 읽어 expected digest로 고정하고, `--dry-run`이면 계획만 보여 준다. 같은 `--id`로 다시 실행하면 저장된 원 요청을 이어 보낸다.

## User 메시지와 서명 action

Unix와 네트워크 MYDCP의 기존 User envelope·로그인·request proof·유한 EOF 계약을 사용한다. 다른 selector·Node·After는 허용하지 않는다.

| Method | 입력 | Reply의 고유 필드 |
|---|---|---|
| `registry-maintenance-plan` | `Tenant`, `RegistryMaintenance:{Action,ID,Repository,Reference,Digest,External?}` | `RegistryMaintenancePlan` |
| `registry-maintenance-status` | `Tenant`, `RegistryMaintenance:{Operation}` | `RegistryMaintenanceStatus` |

계획 Action은 `delete-registry-image` 또는 `gc-registry`다. External은 선택 bool이며 생략/false는 내장, true는 외부 source를 선택한다. GC와 상태 조회에는 true를 허용하지 않는다. GC의 Repository/Reference/Digest, 계획의 Operation, 상태 조회의 Action/ID/Repository/Reference/Digest는 빈 문자열이어야 한다. Schema/Nonce 등 공통 필드는 [Unix 소켓 API](unix-sockets.md)를 따른다.

```json
{
  "Method": "registry-maintenance-plan",
  "Tenant": "payments",
  "RegistryMaintenance": {
    "Action": "delete-registry-image",
    "ID": "private",
    "Repository": "team/app",
    "Reference": "stable",
    "Digest": "sha256:<64 lowercase hex>",
    "Operation": ""
  }
}
```

계획은 `{Schema:1,Cluster,Tenant,Action,Expected,RootRevision,Epoch,Change,InUse}`다. Cluster는 32바이트 배열이다. Expected는 registry 정의 또는 외부 source record revision, RootRevision은 `control/registry-maintenance` root의 revision이다. Change는 `{Tenant,Operation,Run,Repository,Reference,Digest,External?,Prune?}`이며 Operation은 계획에서 비어 있다.

Run은 `{Generation,SpecRevision,Spec,Owner,Principal,DefinitionDigest,OriginDigest,Consumer,Budget,Draining}`의 원 registry run 참조다. Spec은 `registries`의 원 Specification, Consumer/Budget은 그 run이 예약한 Volume·예산 참조다. Owner와 두 digest는 32바이트 배열이다. 새 작업은 enabled·serving·비 drain run만 선택하며 Ready heartbeat는 서명 target에서 제외한다. 관측 갱신을 새 registry 세대로 오인하지 않는다. 비밀값·사용자 Session·원 서명은 이 계획에 포함하지 않는다.

외부 Change의 Run은 영 값이며 External이 `{Selection,Spec,Node,Owner,Revision,ReadSet}`로 원 승인 reader를 고정한다. Selection은 `{Tenant,ID,Generation}`, Spec은 원 source의 참조 전용 정의, Revision은 source record CAS다. ReadSet은 기존 reader 승인/leaf 읽기 집합의 32바이트 지문이다. 원 자격·CA 값은 들어가지 않는다. 현재 가장 구체적인 repository source와 승인 read-set이 바뀌면 새 효과를 거부한다. 내장 Run과 External을 동시에 채울 수 없다.

실행은 별도 unsigned method가 아니라 기존 signed `UserOperation.Change`다.

| Change 필드 | 값 |
|---|---|
| Action | `delete-registry-image`, `gc-registry` 또는 `prune-registry-images` |
| Expected | 계획의 Expected |
| Payload | 계획 Change의 Operation만 안정적인 원 작업 ID로 채운 객체 |
| UserOperation.RootRevision | 현재 maintenance root CAS |
| UserOperation.Epoch | 원 작업의 module epoch |

원 CLI journal이 있으면 동일 Action/tenant/registry/repository/reference/digest와 원 Run·Expected·Epoch를 사용한다. 다른 target으로 바꾸거나 새 run의 계획으로 원 intent를 덮어쓰지 않는다. 전송 결과가 불명이면 원 request ID/result를 조회하고 필요한 경우 `--resume-original`로 같은 서명 작업만 재개한다.

## 진행과 결과

typed action의 `Applied`는 공유 job의 **수락**이다. 실제 이미지 삭제나 디스크 회수 완료를 뜻하지 않는다. CLI는 수락에 `status:accepted`, 전송 불명에 `status:unknown,original_intent_preserved:true`를 출력한다. 실제 상태는 maintenance-status에서 읽는다.

상태 형식은 `{Schema:1,Tenant,Operation,Action,User,State,Revision,RootRevision,At,Change,Result?}`다. User는 원 실행자 ID, At은 마지막 공유 진행의 Unix 초다. 상태는 `queued` → `running` → `done` 또는 `failed`다. 외부 DELETE 결과 유실은 종결되지 않은 `unknown`이며 원 target/fence를 보존한다. queued/running/unknown에는 Result가 없다. 결과는 다음과 같다.

| Result 필드 | 의미 |
|---|---|
| Code | `OK`, `ALREADY_ABSENT`, `IMAGE_IN_USE`, `REFERENCE_CHANGED`, `DENIED`, `UPLOADS_IN_PROGRESS`, `REGISTRY_BUDGET`, 일괄 작업의 `PARTIAL`·`PREVIEW_UNAVAILABLE` 등 제한 코드 |
| At | 실제 native receipt 또는 확실한 거부 결과의 Unix 밀리초 |
| ReclaimedBytes | 실제 GC가 원 intent의 소유 파일에서 회수한 byte 수. 태그/digest 삭제는 0 |
| Native | 원 native receipt의 SHA-256, 32바이트 배열. 성공에는 필수. 효과 전 확실한 거부는 영 배열일 수 있음 |

`OK`/`ALREADY_ABSENT`만 done이다. 이미 없는 원 reference는 ALREADY_ABSENT, 다른 digest로 바뀐 태그는 REFERENCE_CHANGED다. IMAGE_IN_USE는 현재 Task·수락 앱·CD 후보/직전 버전·진행 빌드 등의 공통 참조 검사 결과다. 모르는 과거 참조도 사용 중으로 보호한다. CLI 상태 조회는 failed에 종료 코드 3, unknown에 종료 코드 4를 사용한다. timeout·quorum/DB 오류를 성공이나 확실한 거부로 바꾸지 않는다.

REGISTRY_BUDGET는 원 metadata transaction 전, manifest/blob 변경 없이 확인된 record/byte 한도 거부다. 해당 작업의 원 fence를 정산한 뒤 실패 결과로 남기며 DB write/sync 실패의 불명을 이 코드로 바꾸지 않는다.

`registry list/show`의 행은 선택 `Maintenance:{PendingOperation?,PendingState?,LastGCOperation?,LastGCAt?,ReclaimedBytes}`를 포함한다. LastGCAt은 마지막으로 완료한 GC의 Unix 밀리초이고 ReclaimedBytes는 그 GC 한 건의 결과다. 실패·진행 중인 GC나 단순 여유 공간 변화로 갱신하지 않는다. 정의와 요약을 여러 페이지에서 합칠 때는 `RegistriesRootRevision`과 `RegistryMaintenanceRootRevision`이 모두 같아야 한다.

## 내장 registry 실행·보존 경계

태그 삭제는 해당 별칭·게시 시각만 제거한다. digest 삭제는 원 manifest와 이를 가리키는 현재 별칭을 제거한다. 다른 index/subject가 해당 manifest를 참조하면 거부한다. config/layer 파일은 별도 명시 GC에서만 회수한다. [이미지 사용처](image-usages.md)의 같은 코어를 실제 변경 직전에 다시 검사한다.

수락된 작업은 같은 registry의 새 push 발급과 해당 이미지의 새 Task/CD/compiler 참조를 막는다. GC는 같은 registry 전체에 대해 이 참조 유입을 막는다. 기존 실행 컨테이너를 자동 종료하지 않는다. 이미 발급된 push 자격은 원 만료 범위에서 마치게 하고, 그 범위와 진행 중 native 요청·reader·upload가 끝난 뒤 정리한다. 임의 timeout을 push 종료 증명으로 삼지 않는다.

registry stop/정의 교체·drain은 원 작업이 정산될 때까지 수락하지 않는다. 권한 회수 뒤 새 native 효과는 금지하지만, 원자적으로 기록된 삭제/GC intent의 복구·양성 원 결과 보고는 원 owner가 이어간다. 원 pin과 DB를 반환하기 전에 공유 drain을 확정하므로 미정산 작업과 물리 종료가 서로 추월하지 않는다.

원 native receipt는 같은 registry DB/Scope/작업 ID/target에 묶는다. 재게시된 같은 digest가 있어도 과거 receipt 조회가 다시 지우지 않는다. GC의 detach intent·unlink·sync·최종 결과와 push fence 반환은 원 DB에서 복구한다. 앱 종료·registry 정지가 원 이미지나 Volume 데이터를 자동으로 지우지 않는다.


## 외부 registry 삭제

```sh
mydc --tenant payments image delete company team/app@sha256:<digest> --external --dry-run
mydc --tenant payments image delete company team/app@sha256:<digest> --external --id external-delete-44
```

기존 source reader의 실제 SecretFetch/승인·tenant CA·정확한 authority를 사용한다. 외부 서버에는 SDK의 `push,pull,delete` 범위로 인증하며 원 자격을 사용자에게 반환하지 않는다. SDK 기본 retry를 끄고 동일 target의 DELETE 전송을 한 번으로 제한한다. 실제 전송 직전에 현재 사용자 동작 허가·source specificity/read-set·공통 이미지 참조를 재검사하고 원 Sent fact를 동기 저장한다. 전체 호출은 최대60초이며 그 전에 만료되는 호출 context도 따른다.

- 원 DELETE의 HTTP 200/202는 OK, 같은 원 요청의 404 응답은 ALREADY_ABSENT다. 401/403은 DENIED, 405/501은 UNSUPPORTED다. 서버 body·헤더·원 credential은 결과에 넣지 않는다.
- generic OCI DELETE에는 mutable tag와 expected digest를 원자적으로 비교하는 계약이 없다. 외부 tag-only 삭제는 UNSUPPORTED다. 태그 요청을 digest 삭제로 바꾸어 다른 태그까지 제거하지 않는다. 외부 digest 삭제의 alias/retention 동작은 해당 서버의 OCI 정책을 따른다.
- DELETE 전송 뒤 응답 유실·timeout·모호한 서버 오류는 unknown이다. 이후 GET/HEAD의 404, source 재등록, 새 작업 ID로 원 성공을 만들어내지 않는다. 확인된 원 HTTP 응답을 저장했다면 권한 회수 뒤에도 그 원 결과만 보고한다. 저장된 결과 없이 Sent만 남은 원 작업은 다시 전송하지 않으며 자동 정산되지 않는다.
- unknown의 이미지 fence는 source 이름·tenant를 바꾸어 우회할 수 없다. 외부 publisher의 작업은 MyDC가 잠그지 못하므로 동일 digest가 나중에 재게시될 가능성을 포함해 재전송을 금지한다.
- 자격 reader의 수명과 원격 이미지 효과는 구분한다. 실제 로컬 Secret/HTTP I/O가 join되면 source reader는 원 서명 closure로 사용 참조를 반환할 수 있고 Closed에 원 증거를 보존한다. 이 반환이 remote unknown을 정산하지 않으며 pending 이미지 target·원 job·node/원장 보존은 계속 유지한다. 같은 source의 다른 이미지를 위한 자격 회전을 원격 결과 유실 때문에 영구 봉쇄하지 않는다.


## 일괄 정리

한 번의 `prune-registry-images` 사용자 작업이 고정된 목록의 항목들과 선택 GC를 소유한다. 항목별로 새 사용자 작업을 만들지 않는다. 기존 `ManageRegistry`·credential 동작 제한·사용자 승인·tenant/원 registry CAS를 적용하며, GC를 선택하면 `gc-registry` 동작 허가도 필요하다.

```sh
mydc --tenant payments registry prune private --repository team/app --keep 3 \
  --exclude-tag 'release-*' --gc --dry-run
# 목록을 검토한 뒤 실행한다. 명령은 같은 목록을 다시 보여 주고 묻는다.
mydc --tenant payments registry prune private --repository team/app --keep 3 \
  --exclude-tag 'release-*' --gc --id prune-45
mydc op show prune-45
```

| 조건 필드 | 형식·선택 |
|---|---|
| Repositories | 정확한 이름의 정렬된 배열, 최대256개. 비우면 선택 registry의 전체 repository |
| KeepRecentPerRepository | repository별 최근 태그 보존 수, 0~16384 |
| Before | 절대 Unix 밀리초. 0은 기간 제한 없음. cutoff와 같은 시각은 보존 |
| ExcludeTags | 정렬된 `path.Match` 태그 glob, 최대32개. `/`·escape는 허용하지 않음 |
| IncludeUntagged | 처음부터 태그가 없는 digest 포함. 외부 OCI의 불완전 열거에서는 true를 거부 |
| ProtectedDigests | 보관한 앱 등 소비자가 넘기는 정렬된 SHA-256 digest, 최대256개. 모든 별칭 보호 |
| GC | 내장 registry에서 항목 처리 뒤 같은 원 부모 ID로 registry 전체 GC. 외부 registry는 false만 허용 |

현재 Task·수락 앱·CD 후보/직전 버전·빌드 참조는 서버가 같은 공통 사용처 코어에서 추가한다. 사용처가 생긴 항목은 실제 효과 직전에 다시 거부하며 나머지 원 항목은 이어간다. 게시 시각이 없을 때는 기간 또는 최근 보존 조건에 `UPLOAD_TIME_UNKNOWN`으로 남긴다. 기간·최근 조건이 없는 명시 전체 정리는 시각 부재만으로 제외하지 않는다. 다른 index/subject가 보존하는 manifest도 보호한다.

일부 태그만 선택하면 태그만 제거하고, 모든 태그가 선택되면 해당 digest와 그때의 전체 태그 집합을 고정한다. 내장 registry는 실제 transaction 직전에 별칭 지문을 비교하여 새 별칭을 삭제 범위에 넣지 않는다. parent manifest는 child보다 먼저 처리한다. 목록은 최대16384행, graph edge는 최대16384개이며 원 preview 본문은 최대8MiB다.

### 메시지와 공개 페이지

| Method | 입력 | 응답 |
|---|---|---|
| `registry-prune-preview` | `Tenant`, `RegistryPrune:{ID,External?,Part,Conditions,Fact?}`, `After?` | `Reply.RegistryPrune:{Schema:1,Tenant,Plan,Page}` |
| `registry-prune-results` | `Tenant`, `RegistryPrune:{Operation,Part:"items"}`, `After?` | 같은 형식의 원 항목 결과 페이지. 현재 Read 또는 ManageRegistry |

`Part`는 preview에서 `items` 또는 `retained`다. 첫 요청에는 Fact/After가 없고, 후속 페이지는 첫 응답의 Fact와 원 Conditions를 그대로 보낸다. section을 바꿀 때 After를 비운다. preview Fact는 발행부터600초 유효하며 대상 run/source·조건이 달라지면 거부한다. 일반 `registry-maintenance-plan`은 일괄 action의 우회 입력으로 사용할 수 없다.

Plan은 기존 maintenance 계획 형식이며 `Action:prune-registry-images`다. `Change.Prune:{Conditions,Fact}`가 추가되고 `Repository/Reference/Digest`는 비운다. Fact는 `{Schema:1,Cluster,Owner,Target,Conditions,Preview,Tenant,Registry,External,Items,Retained,ImageBytes,EstimatedReclaimedBytes,EstimateKnown,Live,At,Signature,Public}`다. At은 Unix 초, Signature는 Ed25519 byte의 JSON base64, 각 지문/키는32바이트 배열이다. 원 owner가 `mydc-registry-prune-fact-1\x00` domain과 Signature=nil인 JSON에 서명한다. Target은 Operation/Prune를 비운 원 Change 지문, Conditions는 정규 조건 지문, Preview는 전체 원 선택 지문, Public은 공개 Items/Retained 투영의 별도 지문이다.

Page는 `{Schema:1,Root,Part,Total,Processed,Rows?,Retained?,Next}`다. 한 페이지에 최대8행이다. preview Root는 Preview 지문이고 Processed는0이다. `Rows`는 `{ID,Image,Aliases,AliasDigest}`로 [공개 ImageMetadata](registry-images.md)에 별칭 수와 별칭 집합 SHA-256을 붙인다. 수천 개 별칭을 한 wire 행에 넣지 않는다. 보존 행은 `{Image,Code}`이며 `IMAGE_IN_USE`, `PROTECTED`, `EXCLUDED_TAG`, `RECENT`, `UPLOAD_TIME_UNKNOWN`, `TOO_RECENT`, `UNTAGGED_EXCLUDED`, `MANIFEST_DEPENDENCY`, `REPOSITORY_FILTER` 중 사유를 남긴다.

CLI(`registry prune`)는 두 section을 원 Fact로 끝까지 모아 지울 항목과 남길 항목을 보여 주고 Public 지문을 확인한 뒤, 물어보고 같은 Fact로 실행한다. 서명된 큰 목록 본문은 owner의 기존 observations DB에 보관하고 Raft에는 조건·작은 Fact·원 사용자 작업만 넣는다. preview cache는64건·32MiB로 제한한다. 아직 시작하지 않은 만료 preview가 없어지면 `PREVIEW_UNAVAILABLE`로 무효과 실패한다. 시작한 원 작업은 원 preview를 보존한다. 원 CLI journal이 있으면(같은 `--id`) 새 preview 없이 같은 원 intent/result를 사용한다.

결과 Page의 Rows에는 `Code,At,Native`가 추가되고 Total/Processed는 내구 기록된 원 항목 수다. Root는 원 target·처리 수·최종 결과의 snapshot 지문이며 동기화용 해시체인이 아니다. 처리 수가 바뀌면 기존 cursor를 거부한다. 결과 행은 덮어쓰지 않으며 owner의 같은 DB transaction에서 결과 행 저장과 다음 ordinal 갱신을 함께 확정한다.

### 실제 효과와 집계

같은 부모 fence로 내장 push lease·진행 I/O를 정산한 뒤 한 owner pass에서 최대16항목을 처리한다. 원 native receipt를 먼저 읽어 중단 전 효과를 확인하고, 새 효과 직전 현재 권한·실제 사용처·별칭을 검사한다. Unknown·실패 DB를 새 작업이나 빈 DB로 바꾸지 않는다. 권한이 회수되면 새 효과를 거부하되 확인된 원 결과/GC intent는 같은 원 ID로 정산한다.

최종 `Result.Prune`는 `{Processed,Deleted,Skipped,Failed,GCCode?,GCAt?}`다. Deleted는 OK/ALREADY_ABSENT, Skipped는 IMAGE_IN_USE/REFERENCE_CHANGED, Failed는 확실한 나머지 거부 수다. GCAt은 성공한 실제 GC의 Unix 밀리초다. 모든 원 항목이 정산되고 요청한 GC의 결과가 있어야 최종 보고한다. 실패 항목이나 GC 실패가 있으면 Code=PARTIAL로 failed이며 사유 행을 유지한다. `ReclaimedBytes`는 실제 GC 결과만 사용한다. `ImageBytes`는 고유 repository/digest의 논리 용량, preview의 예상 회수 byte는 보존 graph가 공유하지 않는 고유 물리 blob의 보수적인 예상치다. 예상치를 실제 회수량으로 보고하지 않는다.

외부 선택은 `--external`로 고정한다. 외부 목록은 Live=true이며 게시 시각·untagged 전체·물리 회수량을 알 수 없다. 전송 직전에 보이는 별칭 변경은 REFERENCE_CHANGED로 제외하지만 OCI의 목록 조회와 DELETE를 원자화하지 못하므로 외부 동시 writer에 대한 CAS를 보장하지 않는다. tag-only는 UNSUPPORTED다. digest 단회 DELETE가 불명해지면 부모 전체를 unknown으로 보존하고 이후 항목을 보내지 않는다. source reader의 실제 I/O join은 원격 이미지 작업의 완료와 별개다.

Repositories는 삭제 항목의 선택 범위다. GC=true이면 기존 registry 전체 GC를 별도로 허가하는 것이므로 같은 부모가 해당 authority 전체의 새 이미지 참조를 막고, 다른 repository의 원 retired blob도 현재 사용처를 검사한 뒤 회수할 수 있다. 삭제 필터 때문에 GC의 사용처 검사를 생략하거나 다른 repository의 새 소비가 회수와 경합하게 하지 않는다.
