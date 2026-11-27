## 설치 신원 경로와 관리 도구의 분리

기존 설치 신원의 `status/get/observe/plan/submit/result/command`는 해당 키의 실제 정책·원 namespace/요청에 한정한다. user 인증이 실패했다고 이 경로로 자동 fallback하지 않는다. 범용 관리자 권한으로 해석하지 않는다.

`sfcd --config NODE.yaml run/check/init/join`은 지정 노드 설치/실행·bootstrap 경로다. run은 node.management_socket(생략=/run/sfcdp.sock)에 관리 listener를 bind하며 check/init/join은 공통 socket을 열지 않는다. 기존 경로는 덮어쓰지 않고 같은 node TLS/user 인증을 적용한다. `sfcli`의 로컬 cluster 등록이나 전역 selector가 daemon의 설치 신원/DB/투표 구성을 암묵적으로 바꾸지 않는다. init/join의 빈 초기 상태·승인은 bootstrap을 따른다.

