## Managed 대상 가입 CLI

`sfcd --config NODE.yaml join --cluster CLUSTER --source-public-key CONTROL_PUBLIC_KEY --invitation ORIGINAL.json`은 기존 target identity/ID/listener와 원 초대가 일치해야 실행한다. cluster/control key는 파일에 담긴 값만으로 신뢰하지 않고 외부 pin을 요구한다. timeout은 기본30초·최대5분이며 실패/단절 시 원 Join/cluster/key/ACK를 보존한다. 같은 초대의 재실행은 원 DB를 재개하고 새 init/가입 ID로 바꾸지 않는다.

초대는 현재 system-admin의 invite-node UserOperation 승인 뒤 userauth.Client.NodeInvitation API로 출력한다. target key는 `sfcli identity create DIR`로 미리 준비한다. 사용자 승격은 별도 promote-node API이며 sfcli node lifecycle 명령은 D5.15에서 제공한다. CLI join이 종료한 뒤 `sfcd --config NODE.yaml run`으로 운영한다. run은 저장된 의도에 따라 원 설치를 재개한다. [가입 예시](../../../configs/node.join.example.yaml)와 bootstrap 계약을 따른다.


현재 보호 로그인 예시는 sfcli --config FILE login --username USER --method password --password-stdin과 --method token --token-stdin이다. stdin 플래그를 생략하면 숨김 TTY를 요구하고 pipe로 자동 전환하지 않는다. 같은 method의 활성 credential이 여러 개면 --credential ID를 명시한다. --password VALUE/--token VALUE·환경변수 credential 입력은 제공하지 않는다. node의 credentials profile과 system Vault material을 먼저 설치해야 하며 user profile에는 provider 자격을 쓰지 않는다.

