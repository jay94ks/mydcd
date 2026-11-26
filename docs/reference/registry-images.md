# Registry 이미지 목록

선택 tenant의 내장 registry 또는 승인된 외부 source에서 repository·이미지 metadata를 읽는다. 로그인·이미지 trust 추가·배포·이미지 삭제를 수행하지 않는다. 인증은 기존 사용자 Session/request proof를 사용하며 현재 tenant의 Read 또는 ManageRegistry가 필요하다.

```sh
mydc --tenant payments image list private
mydc --tenant payments image list private team/app
mydc --tenant payments image list company --external
mydc --tenant payments image list company team/app --external
```

`private`는 내장 registry 이름, `company`는 같은 tenant의 외부 source 이름이다. 외부 source는 [명시 reader 승인](external-registries.md#앱-없는-관리-source-승인과-로그인-시험)이 있어야 한다. 조회는 그 원 reader의 자격/CA와 현재 승인 read-set을 사용한다. 호출 사용자의 Read 권한을 Vault 원문 읽기 권한으로 바꾸지 않는다. 다른 tenant·authority의 source를 선택할 수 없다.

## 메시지

User method는 `registry-catalog`다. 공통 Schema=1·Nonce·사용자 envelope·유한 EOF 규칙은 [Unix 소켓 API](unix-sockets.md)를 따른다. method 고유 입력은 다음과 같다.

```json
{
  "Method": "registry-catalog",
  "Tenant": "payments",
  "RegistryCatalog": {"Kind": "managed", "ID": "private", "Repository": "team/app"},
  "After": ""
}
```

| 입력 | 의미 |
|---|---|
| Kind | `managed` 또는 `external`. 이름이 같아도 종류를 명시한다 |
| ID | 현재 tenant의 registry/source 이름 |
| Repository | 비우면 repository 목록. 지정하면 정확한 repository의 태그/다이제스트 목록. URL·이미지 tag·digest·경로 패턴은 받지 않는다 |
| After | 이전 응답의 Next. 임의 offset·다른 사용자/선택의 cursor로 바꾸지 않는다 |

응답 `Reply.RegistryCatalog`는 `{Kind,ID,Page}`다.

| Page 필드 | 의미 |
|---|---|
| Schema | 1 |
| Authority, Repository | 실제 선택한 주소·repository |
| Code | `OK`, `UNAUTHORIZED`, `DENIED`, `NOT_FOUND`, `UNSUPPORTED`, `UNAVAILABLE`, 취소/기한·이미지/metadata 예산 등의 제한 코드 |
| Root | 현재 허가된 목록·source/owner 세대·승인 read-set·사용자/선택을 고정하는 32바이트 배열 |
| Repositories | repository 이름 배열. Repository가 비었을 때만 반환 |
| Images | 아래 이미지 행 배열. Repository를 지정했을 때만 반환 |
| Live | 외부 서버의 list/manifest 읽기 사이에 원자 snapshot이 없으면 true |
| UntaggedComplete | 내장 저장소의 태그 없는 digest까지 포함한 참조 목록이면 true. 외부 표준 OCI tag 목록은 false |
| Next | 다음 페이지 cursor. 끝이면 빈 문자열 |

각 페이지는 최대 8행이다. 오류 Code에는 부분 목록·원격 body·응답 header·원 credential을 넣지 않는다. 이름이 허가되지 않으면 `denied`, source/serving 준비가 충족되지 않거나 페이지 기준이 변경되면 `conflict`를 반환할 수 있다. 외부 catalog/tags API가 없으면 `UNSUPPORTED`, 거부하면 `DENIED`/`UNAUTHORIZED`로 구분한다.

이미지 행의 형식은 다음과 같다.

```json
{
  "Repository": "team/app",
  "Reference": "stable",
  "Digest": "sha256:<64 lowercase hex>",
  "MediaType": "application/vnd.oci.image.manifest.v1+json",
  "ManifestBytes": 714,
  "ImageBytes": 10485760,
  "UploadedAt": 1795300000000,
  "UploadedAtKnown": true
}
```

- `Reference`는 태그 또는 `sha256:...` 원 digest다. 여러 태그가 같은 digest를 가리킬 수 있고, 내장 목록은 digest 자체 행도 포함한다. 이미지 수·회수 예상량을 계산할 때 같은 digest를 중복 계산하지 않는다.
- `ManifestBytes`는 해당 manifest/index 원문 크기다. `ImageBytes`는 검증된 graph의 고유 config/layer descriptor의 압축 크기 합이다. index는 자식 manifest를 같은 repository의 고정 digest로 따라가며 공유 blob을 한 번만 센다. 실제 디스크 할당량·GC 회수량·컨테이너 쓰기층 크기가 아니다.
- `UploadedAt`은 내장 저장소가 해당 reference를 현재 digest로 게시한 Unix 밀리초다. digest 행은 최초 게시 시각을 유지하며 태그를 다른 digest로 바꾸면 그 태그의 시각을 갱신한다. 같은 내용의 재시도는 시각을 바꾸지 않는다.
- 기존 데이터에 게시 fact가 없거나 외부 서버가 업로드 시각을 제공하지 않으면 `UploadedAtKnown=false,UploadedAt=0`이다. image config의 Created·DB 수정 시각을 업로드 시각으로 대신하지 않는다.

## 일관성과 격리

내장 Store는 기존 metadata mutex와 같은 DB의 하나의 view에서 이름·digest·게시 fact를 읽는다. 게시 fact와 원 manifest/별칭은 같은 동기 트랜잭션에서 커밋한다. 복구 시 잘못된/고아 fact는 거부하고 원문을 임의 복구하거나 시각을 채우지 않는다. 목록·metadata를 읽기 위해 별도 DB나 Volume writer를 열지 않는다.

외부 source의 정확한 authority·repository specificity를 재사용한다. catalog가 더 넓은 이름 목록을 줘도 선택 source가 실제 담당하는 repository만 반환한다. 더 구체적인 source가 따로 있으면 넓은 source로 그 이름/이미지를 읽지 않으며, 삭제된 좁은 source를 익명/넓은 자격으로 대체하지 않는다. 읽기 도중 source·scope·reader·승인 read-set이 바뀌면 결과를 폐기한다.

내장 cursor는 이름·digest·게시 fact를 고정한다. 외부 cursor는 source와 현재 허가된 이름 집합을 고정하지만, 외부 서버가 태그를 같은 이름으로 재지정하는 것을 전체 페이지에 걸쳐 원자적으로 막을 수 없다. `Live=true`의 각 행은 그 행을 읽을 때 확인한 고정 digest다. 표준 OCI API로 보이지 않는 외부 untagged digest나 업로드 시각을 추측하지 않는다.

이 API는 사용 여부나 삭제 허가를 보장하지 않는다. 현재 참조는 [이미지 사용처](image-usages.md)에서 읽고 삭제 실행 직전에도 재검사해야 한다. CLI는 같은 Root의 페이지를 모아 출력하며, 집계 출력은 단일 8행 wire page와 구분한다.

이 문서의 User/CLI API는 목록 조회다. 명시 쓰기 action과 실제 완료/원 결과는 [이미지 삭제·GC](registry-maintenance.md)를 따른다. 원 native receipt 재조회는 과거 결과이며 이후 재게시된 이미지의 현재 존재/삭제 상태를 뜻하지 않는다.


내장 목록의 owner/run 기준에서 주기적 Ready·boot 관측은 metadata 내용 세대가 아니다. enabled·원 writer/세대·실제 열린 Store와 현재 허가는 별도로 재검사하며, 정상 관측 갱신만으로 내용이 같은 페이지 root를 바꾸지 않는다. 정의 교체·stop·실제 별칭/게시 fact 변경은 계속 이전 기준을 무효화한다.
