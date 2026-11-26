## 사용자 로그인·tenant 선택

username과 password/private-key/token 중 활성 방식 하나로 로그인하고 계정별 최소1개 인증수단을 유지한다. 한 계정의 여러 tenant membership과 system admin의 암묵적 전체 tenant 관리 권한을 구분한다. 현재 auth:user profile은 password/private-key/token login·whoami/logout를 지원한다. 작업 공간 목록은 `mydc tenant list`다. compose를 포함한 사용자 명령은 전역 `--cluster/--tenant/--user` 선택 규칙을 사용한다. 설정 탐색 순서와 기존 원 요청 불명/무자동재전송 계약은 유지한다. user 인증용 연결/세션과 node 공개키/Member 권한은 별도이며 password/token 원문을 client YAML/argv에 쓰지 않는다. 이미지 신뢰 정책의 list/add/remove는 자기 tenant에만 적용하고 tenant 초기값은 Docker Hub만이다.

