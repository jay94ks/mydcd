## 클러스터 내부 웹훅 호출

- `POST /t/{t}/apps/{app}/call` `{service, port, path, headers?, body?(base64) | text?, timeoutMs?, scheme?: http|https, insecureSkipVerify?}` → `{code?, status?, contentType?, body?(base64), task?, node?, elapsedMS}`(sfcd `service-call`, REQ-24/55. `contentType`은 결과 `Headers["Content-Type"]`). 작업 공간 망 안에서 그 서비스 포트로 POST 하나를 보낸다. 대상은 작업 공간/앱/서비스/포트뿐이고 IP·호스트 이름은 받지 않는다. sfcd가 준비된 Task를 고르고 권한(`CallService`, 가짜는 관리자)을 판단한다. path는 `/`로 시작, 헤더는 `Content-Type`·`X-SFC-*`만, 본문 256 KiB, 응답 64 KiB, timeoutMs 0..30000(0이면 10초).
- 호출 실패는 오류가 아니라 200의 `code`다: `SERVICE_NO_READY_TASK`·`SERVICE_CALL_TIMEOUT`·`SERVICE_CALL_REFUSED`·`SERVICE_CALL_TOO_LARGE`·`RATE_LIMITED`. 입력·권한 오류는 422/403이다. op가 아니고 작업 기록에 남지 않으며, 웹은 요청과 응답을 저장하지 않는다.

