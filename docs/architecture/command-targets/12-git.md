## 서비스·Git 진단 대상

| 명령 | 주체·현재 권한 | 적용 대상·효과 | 원 결과/재개 |
|---|---|---|---|
| `service-call APP SERVICE --port N --path PATH [--scheme http\|https] [--insecure-skip-verify] [--header NAME=VALUE] [--body-file FILE] [--timeout-ms N]` | 현재 User Session·tenant CallService·해당 node ACL·credential operation ceiling | 선택 tenant의 현재 Healthy Task에 한 번 POST; host/IP/redirect/임의 header 금지 | body 길이/digest/EOF 이후 실행; timeout/단절은 미실행 증거가 아니며 자동 재전송·operation 생성 없음 |
| `cd probe APP --repository HTTPS_URL --branch BRANCH --path FILE [--credential INSTALLED_NAME]` | 현재 User Session·tenant Deploy·해당 node ACL·credential operation ceiling | 기존 앱 scope에서 원 Git provider의 고정 commit/파일 크기/실행 Node 읽기; policy/candidate/app 불변 | 읽기 전용, 사용자 ID별 제한, 원 provider 오류문·secret 출력 없음 |

두 명령은 전역 cluster/tenant/user 선택과 기본 Unix 접속을 따른다. CA는 node 설치 설정 `service_cas`의 tenant별 읽기 전용 bundle이고 app 자원이 아니다. 내부 `service-call-permit`은 member 전용 현재 quorum 확인이며 사용자의 권한을 발급하지 않는다. [전체 명세](../../reference/service-diagnostics.md)를 따른다.

