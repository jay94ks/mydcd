## Lifecycle 원본 도구

| 명령 | 주체·권한 | 대상·효과 | 원 결과/읽기 |
|---|---|---|---|
| `lifecycle source stage` | 현재 User ManageServices·provider node ACL·lifecycle-source-upload ceiling | tenant의 원 descriptor/token으로 선택 provider에 source를 보관; resolver·타입 검사 후 fact 반환 | 줄/열 진단 때 fact 없음; 원 provider/token 보존, 자동 재전송 없음 |
| `lifecycle source module` | 같은 현재 사용자/provider 권한 | 원 source lock에 포함된 ZIP을 같은 provider에 보관 | 명시 source-file/modules/module/file/upload, 새 버전 다운로드 없음 |
| `lifecycle source recover` | 현재 사용자 원 기록 복구 권한 | 명시 원 provider/descriptor/upload의 기존 fact | 새 source/업로드 생성이나 등록 없음 |
| `lifecycle source read NAME --revision N` | 현재 tenant ManageServices·명시 Session/credential ceiling | 이름의 정확한 immutable source version 원문 | 현재/이전 nondeleted 버전만; 삭제는 missing, 전체 길이/digest 검증 |

전역 cluster/tenant/user 선택을 따른다. 기존 script put/retire/delete의 관리 operation/CAS·wallet journal은 별개다. [전체 계약](../../reference/lifecycle-sources.md)을 따른다.
