## 설치 키 교체 복구

설치 키 교체의 원 활성화 복구는 `mydcd`가 내구 준비된 새 키와 기존 MYDCP quorum 관측으로 수행한다. CLI 상시 실행·재로그인·추가 profile 옵션을 요구하지 않으며 옛 TLS pin을 자동 신뢰 fallback으로 사용하지 않는다. 운영자는 원 `node rotate-identity` 작업의 진행을 조회한다.

lifecycle과 ingress 명령은 [mydc lifecycle](../../cli/lifecycle.md), [mydc ingress](../../cli/ingress.md)에 있다.
