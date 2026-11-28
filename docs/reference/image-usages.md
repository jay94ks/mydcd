# 이미지와 외부 source의 사용처

이미지 사용처는 현재 tenant의 공유 상태에서 읽는다. 실제 Task 선언, 수락된 앱 실행·남아 있는 claim, 교체 중 원 컨테이너, CD 후보/연속성 계획, 직전 앱 버전, 진행 중 lifecycle compiler job을 구분한다. 컨테이너의 현재 생존 여부는 [Task·컨테이너 관측](container-operations.md)에서 별도로 확인한다.

```sh
sfcli --tenant payments image usages IMAGE_OR_DIGEST
sfcli --tenant payments image usages --source SOURCE_NAME
```

Read 또는 ManageRegistry 권한이 필요하다. 관리 operation이나 자격 입력을 만들지 않는다. CLI는 페이지를 모두 모으고 동일한 공개 결과 root인지 확인한 뒤 출력한다. 중간에 사용처가 바뀌면 부분 목록을 정상 결과로 내지 않는다. CLI 수집은65536행 이내이며 더 큰 결과는 아래의 페이지 API로 읽는다.

## User 메시지

기존 User envelope·Session·Nonce·finite EOF 계약을 사용한다.

```json
{
  "Schema": 1,
  "Method": "image-usages",
  "Params": {
    "Tenant": "payments",
    "Query": {
      "Refs": ["ghcr.io/my-org/app:release"],
      "ExternalSource": "ghcr"
    },
    "After": ""
  }
}
```

`Refs`는 선택 사항이며 최대32개의 image ref 또는 `sha256:` digest다. 이름은 같은 OCI parser로 정규화하고 같은 이름으로 정규화되는 중복 입력은 거부한다. `ExternalSource`는 선택 tenant의 외부 source 이름으로, 삭제된 정의도 원 사용처를 조회할 수 있다. 두 selector를 함께 주면 교집합을 읽고 둘 다 비우면 해당 tenant의 전체 사용처를 읽는다. 다른 tenant의 source나 존재하지 않는 source를 지정하면 거부한다. typed method라 `Params`의 다른 필드(Node·자격 입력 등)는 받지 않는다.

응답 `Data`는 다음 형식이다.

| 필드 | 내용 |
|---|---|
| `Schema`, `Tenant` | 1, 선택 tenant |
| `Root` | 정규화한 query·사용자 scope·허가된 결과 행을 고정한 SHA-256 |
| `Index` | 이 페이지를 계산한 공유 상태 index |
| `Rows` | 최대16개 `ImageUsage` 행 |
| `Next` | 후속 페이지의 opaque cursor. 끝이면 빈 문자열 |

행은 `{ID,Tenant,App,Deployment,Node,Service,Instance,Image,Kind,Task,Operation,Commit,Version?,Unknown?,Match}`다. ID는 이 공개 참조의 안정적인 지문이며 native 실행 ID가 아니다. Task는 원 typed 자원 key이고, 버전/후보처럼 아직 Task key가 없거나 과거 배치를 복원할 수 없는 경우 비어 있을 수 있다. replica의 Service는 논리 이름, Instance는 실제 instance 이름이다. 원 사용자 Session·서명·Vault 값·환경 변수·레시피 본문은 반환하지 않는다.

| Kind | 원 근거 |
|---|---|
| `task-shared` | 공유 Task 목표 |
| `app-execution`, `app-claim` | 수락된 실행과 아직 반환하지 않은 원 claim |
| `app-held`, `app-retiring` | 교체/종료 중 원 native를 보존하는 기존 Inventory |
| `app-previous` | 앱이 유지하는 직전 수락 버전의 원 선언·local service·override |
| `cd-candidate`, `cd-running` | 등록된 CD의 후보/선택 실행 |
| `cd-last-success`, `cd-last-failure`, `cd-transition` | CD가 보존한 연속성/복구 계획 |
| `lifecycle-build` | 종료되지 않은 실제 compiler job의 고정 builder image |
| `lifecycle-compiler/…` | 해당 앱 계획이 참조하는 compile policy image |
| `legacy-task` | 명시 매핑된 과거 Task. 미매핑 legacy 행은 사용자 조회에 노출하지 않음 |
| `app-previous-unknown` | 원문을 보관하지 않은 과거 버전이라 이미지 부재를 증명할 수 없음 |

`Match`는 `exact`, `digest`, `repository-unknown`, `unknown`, `scope`다. bare digest는 named pinned 참조의 manifest digest와 비교한다. named ref는 authority/repository를 함께 비교하므로 다른 registry의 같은 digest를 같은 사용처로 간주하지 않는다. 태그와 digest(또는 다른 태그)가 같은 repository면 `repository-unknown`으로 표시한다. 이는 정확한 digest를 안다는 뜻이 아니다. 태그는 digest로 고정하지 않으므로(devel/design/image-tags.md), `repository-unknown` 행은 저장소 digest 삭제를 막지 않는다. 진행 중인 배포가 태그를 해석한 digest는 그 배포의 `app-execution` 행으로 따로 나오고, 이 행이 그 digest를 지키는 근거다. 이미 만든 컨테이너는 그 서버의 로컬 이미지로 돌기 때문에 저장소에서 지워도 영향이 없다. 다시 만들 때는 태그를 새로 해석하고, 없으면 그 서버의 마지막 사본을 쓴다(Jay 2026-11-28 18:21 KST). 원문 없는 직전 버전은 Image가 비고 Unknown=true이며 `unknown`으로 반환한다.

같은 Task/image가 여러 근거에 등장할 수 있다. 따라서 행 수를 실제 컨테이너 개수로 취급하지 않는다. 과거 버전의 node가 원문에 없으면 현재 기본 노드로 추측하지 않고 Node를 비운다. 직전 버전은 앱 종료로 그 선언 의도가 반환될 때 해제하며, 진행 중 원 native는 별도의 claim/retirement가 계속 보호한다.

## 페이지와 삭제 보호

후속 요청은 같은 query·현재 사용자와 `Next`를 그대로 사용한다. 모든 페이지의 Root가 같아야 한다. 허가된 행이 바뀌면 `conflict`이고, 다른 tenant의 변경이나 무관한 Raft index 증가만으로 cursor를 무효화하지 않는다. 잘못된 cursor나 권한 철회는 거부된다.

공통 참조 코어는 노드 이미지 캐시의 공유 참조 검사에도 사용한다. 직전 원문이 없어 부재를 증명할 수 없으면 캐시 회수를 허용하지 않는다. 실제 효과 직전에는 새 참조와 native/private 상태를 다시 검사해야 한다. 이 목록의 빈 페이지·오래된 root·웹에 보관된 앱만으로 삭제를 승인하지 않는다. typed registry 삭제/GC의 구현·검증 범위는 해당 명령 명세를 따른다.
