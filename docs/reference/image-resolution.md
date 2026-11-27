# 이미지 참조 확인

`image-resolve`는 태그를 immutable digest로 확인하고 현재 tenant의 이미지 신뢰 정책을 검사하는 읽기 API다. 이미지 배포·신뢰 출처 등록·credential 발급을 수행하지 않는다. 실제 배포는 실행 직전에 같은 신뢰 규칙과 현재 권한을 다시 검사한다.

```sh
sfcli --tenant payments image show ghcr.io/my-org/app:release
sfcli --tenant payments image resolve docker.io/library/alpine:latest
```

현재 tenant의 Read 또는 ManageRegistry 권한이 필요하다. CLI는 선택 cluster/tenant/user·기본 Unix 접속 규칙을 그대로 따른다. `--node`, 관리 `--request-id`, 자격 출력·Group 비밀번호 옵션은 받지 않는다. 결과 Code가 `OK`면0, 진단상 실패면3으로 종료하며 전송·정책 오류는 기존 CLI 규칙을 따른다.

## 메시지 형식

기존 User envelope·Session·Nonce·서명을 사용한다. Unix와 네트워크 SFCP의 형식은 동일하며 finite 요청의 write EOF 뒤에 응답을 읽는다.

```json
{
  "Schema": 1,
  "Method": "image-resolve",
  "Tenant": "payments",
  "ImageResolve": { "Ref": "ghcr.io/my-org/app:release" }
}
```

위 본문에는 기존 공통 Nonce도 포함해야 한다. `Ref`는 비어 있지 않은 최대1024바이트 이미지 이름이며 tag·digest를 허용한다. `alpine`은 `docker.io/library/alpine:latest`로 정규화한다. 로컬 image ID, URL·인증 정보·공백을 포함한 이름은 `INVALID_IMAGE`다. Node/After나 다른 method의 selector를 섞지 않는다.

성공한 User Reply의 `ImageResolve` 필드는 다음 구조다. 아래 digest는 실제 조회값으로 채워진다.

| 필드 | 형식·의미 |
|---|---|
| `Normalized` | 정규화한 입력 참조. 문법 오류면 빈 문자열 |
| `Kind` | `managed`, `external`, `unknown` |
| `Source` | 내장/외부 source의 tenant 내 이름. unknown이면 빈 문자열 |
| `Code` | 아래의 제한된 결과 코드 |
| `Trust` | `{Trusted,Rules:[{Registry,Repository}]}`. 현재 tenant의 공개 신뢰 규칙이며 신뢰 실패 시 맞지 않는 authority/repository를 확인할 수 있음 |
| `Image` | 해석 성공일 때만 `{Normalized,Registry,Repository,Pinned,Digest,MediaType,ManifestBytes,Platforms?}` |

`Pinned`는 tag를 제거한 `authority/repository@sha256:…`다. manifest list/index라면 `Digest`는 index 자체의 digest이고 `Platforms`는 각 `{Digest,Platform?}`를 보존한다. Platform은 OCI의 OS·architecture·variant 등 공개 descriptor다. 특정 platform 하나의 digest로 index를 바꿔 반환하지 않는다. manifest·config·history 원문·registry 응답 body·인증 challenge·자격은 이 API의 응답에 없다.

## 결과 코드와 조회 경계

| Code | 의미 |
|---|---|
| `OK` | 현재 권한·신뢰 아래 manifest/index를 확인함 |
| `INVALID_IMAGE` | 이름·digest·manifest 형식이 잘못됨 |
| `UNTRUSTED` | 현재 tenant의 정확한 repository 또는 `**` 신뢰 규칙에 맞지 않음. 이 주소에는 네트워크 요청을 보내지 않음 |
| `SOURCE_REVOKED` | 일치하는 외부 source가 삭제/비활성 상태. 넓은 source나 익명으로 fallback하지 않음 |
| `SOURCE_NOT_READY` | 외부 source의 명시 reader bind가 없거나 Draining임 |
| `UNAUTHORIZED` / `DENIED` | 원격 인증 실패 / 접근 거부 또는 승인된 source 읽기 범위 부족 |
| `NOT_FOUND` | repository 또는 tag/digest가 없음 |
| `UNAVAILABLE` | 원격 응답·TLS/연결 문제 또는 내장 registry의 사용 가능한 원 run이 없음 |
| `UNSUPPORTED` | registry의 형식/API가 지원되지 않음 |
| `TIMEOUT` / `CANCELLED` | 해당 조회의 대기 만료/취소 |
| `METADATA_BUDGET` / `IMAGE_BUDGET` | metadata·descriptor 수/선언 용량 한도 초과 |

사내 CA나 자격 정의 오류는 제한된 `INVALID_CA`, `INVALID_CREDENTIAL`, `INVALID_SOURCE` 등으로도 표시할 수 있다. 정책 거부·결과 조립 중 변경은 User Reply 자체의 `denied`/`unavailable`로 끝날 수 있다. 부분 digest를 성공 결과처럼 제공하지 않는다.

내장 registry는 원 담당 노드의 현재 run·writer를 확인하고 이미 열린 Store의 metadata를 잠시 빌려 읽는다. 새 Store/Volume writer를 열거나 읽기 사용자의 권한을 push/pull credential로 확대하지 않는다. 외부 source는 [명시 bind와 승인](external-registries.md#앱-없는-관리-source-승인과-로그인-시험)의 원 reader가 기존 SecretFetch와 요청별 OCI 클라이언트를 사용한다. 호출 계정의 조회 권한을 Vault 원문 읽기 권한으로 바꾸지 않는다. source가 없는 trusted 주소만 익명 HTTPS를 사용하며 ambient Docker 자격·호스트 CA 변경·자격 없는 재시도는 없다.

조회 전후에 현재 Session·tenant 신뢰·선택 owner/run·source 세대와 원 승인 read-set을 대조한다. 노드 간 전달은 인증된 Management의 `image-resolve-owner`로 같은 원 Session·tenant·Ref·해석 대상만 넘긴다. node 전용 호출을 Unix User method로 노출하지 않는다. 내장 Store read는 기존 owner lock으로 close와 합류하고, 외부 read는 source의 세대 fence·실제 HTTP/Secret I/O 반환에 합류한다.

manifest/config metadata 한도와 index의 플랫폼별 digest 검사는 [외부 registry](external-registries.md)의 같은 parser/예산을 사용한다. 공개 결과는224KiB 이내이며 SFCP의256KiB frame 한도 안에 둔다. 이 조회는 layer 다운로드·Docker 적재·실행 성공이나 이후 mutable tag가 그대로임을 보장하지 않는다.
