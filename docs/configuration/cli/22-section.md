## 컨테이너 로그·프로세스·리소스 조회

선택 cluster/tenant의 현재 Read 계정으로 `sfcli app logs APP SERVICE`, `top`, `stats`를 사용한다. 명시 사용자/기본 profile 선택은 기존 규칙을 따르며 임의 Docker ID·host 경로는 받지 않는다. `-o json`, `--instance TASK`, `--max-bytes N`과 로그의 tail/기간/채널 옵션, 단위/미지원/잘림과 담당 노드 경유는 [컨테이너 운영 API](../../reference/container-operations.md)를 따른다. 기본 Unix와 네트워크 SFCP에서 같은 사용자 권한으로 처리한다.

연속 조회는 logs의 `--follow`와 top/stats의 `--watch --interval 2s`를 사용한다. exec는 현재 Read+Deploy로 `app exec APP SERVICE --id ID -i -t -- argv...`, 원 조회는 `app exec APP SERVICE --id ID (같은 ID 재실행)`다. 첫 제출 전 현재 user/profile의 별도 container-execs journal에 원 intent/대상을 저장하며 같은 ID 반복은 상태만 조회한다. login wallet·--user 모호성 오류·현재 TLS pins/독립 승인 규칙은 그대로 적용한다. 접속 timeout과 스트림 수명·terminal/EOF/실제 exit·원 profile 선택은 [상세 사용법](../../reference/container-operations.md#interactive-exec와-원-실행-조회)을 따른다.

