## 단독 컨테이너·Volume 파일 스트림

Unix 관리 접속도 TLS/MYDCP와 같은 원 operation·현재 인증/CAS/quorum을 사용한다. purpose15 standalone `attach`는 원 컨테이너의 I/O에 재접속하며 양방향 stdin EOF와 output EOF를 구분한다. purpose18 Volume 파일 전송은 서명된 유한 header·최대 24KiB chunks·명시 EOF를 사용한다. half-close/단절은 원 파일 effect의 미실행이나 native fence를 뜻하지 않는다. 원 staged inode publication receipt가 없는 put은 기존 동일 내용만으로 성공 처리하지 않는다. Docker Engine의 Unix HTTP attach API는 mydcd 내부 SDK 경계이며 관리 끝점의 인증 대체 경로가 아니다.

### 임시 단독 컨테이너 TTL 연장

`standalone-extend`는 새 purpose나 별도 소켓이 아닌 기존 `User`의 `submit/result/resume` operation이다. Unix와 네트워크 MYDCP가 같은 현재 사용자·Deploy/creator 또는 관리자·Target CAS·Raft 코어를 사용한다. `Schema:1`, `Change.Action:"standalone-extend"`, `Change.Expected:현재 metadata revision`을 원 operation에 서명한다. payload 형식은 다음과 같다(`Target`은 32바이트 digest 배열).

```text
{Tenant, Name, Scope, Operation: string,
 CreatedAt, PreviousExpiresAt, TTLSeconds: int64,
 Target: digest32}
```

`Name`은 공개 이름, `Scope`는 불변 내부 workload 이름이다. 현재 Target과 CreatedAt/이전 만료가 일치하고 temp가 실행 목표·미정리 상태여야 한다. 새 만료는 원 `Operation.At + TTLSeconds`, 생성+86400초 이하이며 이전 만료보다 커야 한다. 신규 제출은 현재 만료도 검사하며 기존 receipt 조회는 먼저 반환한다. 연결 해제 유예·Task/native·원 승인 참조는 변경하지 않는다.

확정 `Reply.Result`/`Found:true`와 함께 선택 `StandaloneExtension:{CreatedAt,At,PreviousExpiresAt,ProposedExpiresAt,MaximumExpiresAt,AllowedTTLSeconds,RemainingExtensionSeconds}`를 반환한다. 이 값은 원 서명에 고정된 제안/계산이며 `Result.Code==Applied`일 때만 적용된 만료다. 거부한 원 결과에는 선택 `StandaloneExtensionCode:STANDALONE_TTL_LIMIT|STANDALONE_TTL_EXPIRED|STANDALONE_TTL_NOT_INCREASED`와 가능한 숫자 한도를 보존한다. 신규 제출의 현재 만료 사전 거부는 `Code:"conflict", StandaloneExtensionCode:"STANDALONE_TTL_EXPIRED"`이며 `Found/Result` 없이 미수락이다. unknown/미확정 결과에 제안 만료를 성공 값으로 붙이지 않는다. 성공한 관리 전이의 `standalone-extended` 이벤트는 원 operation과 tenant/내부 scope/node·새 만료(Detail.Value, Unix초)만 보존한다. [CLI/수명](../standalone.md)을 참고한다.

