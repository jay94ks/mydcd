## init/join·runtime node

bootstrap 명세는 독립 cluster init 또는 대상 cluster join을 선택하고 기존 root는 같은 DB로 복구한다. 자기 member 하나인 확정 구성은 standalone이며 단절/접속 수로 mode/N을 바꾸지 않는다. 새 cluster 운영 catalog는 백지로 두고 최초 username/system admin·tenant는 명시 등록한다. node add/remove/isolate/restore는 system admin의 실행 중 관리 작업이며 같은 구성/과반수·원 작업·native 정산을 요구한다. managed 설치는 [Quick-start](../../quick.md)의 `sfcd init/join/run`과 위 `node` 운영 명령을 사용한다. legacy 고정 peers 예시는 별도 설정이며 그 파일만으로 동적 가입·승격이 완료되지 않는다.

voter 과반을 영구히 잃었을 때는 남은 voter마다 `sfcd --config NODE.yaml recover --voters ... --request-id ...`를 같은 목록으로 실행한다. 자세한 것은 [정족수 복구](../../reference/quorum-recovery.md)다. voter를 모두 잃었으면 새 서버에서 `sfcd --config NODE.yaml restore --backup FILE.sfcbak --backup-key-file KEY --request-id ...`로 클러스터 백업을 되살린다. 자세한 것은 [전체 복구](../../reference/cluster-restore.md)다.
