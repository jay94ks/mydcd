## init/join·runtime node

bootstrap 명세는 독립 cluster init 또는 대상 cluster join을 선택하고 기존 root는 같은 DB로 복구한다. 자기 member 하나인 확정 구성은 standalone이며 단절/접속 수로 mode/N을 바꾸지 않는다. 새 cluster 운영 catalog는 백지로 두고 최초 username/system admin·tenant는 명시 등록한다. node add/remove/isolate/restore는 system admin의 실행 중 관리 작업이며 같은 구성/과반수·원 작업·native 정산을 요구한다. managed 설치는 [Quick-start](../../quick.md)의 `mydcd init/join/run`과 위 `node` 운영 명령을 사용한다. legacy 고정 peers 예시는 별도 설정이며 그 파일만으로 동적 가입·승격이 완료되지 않는다.


