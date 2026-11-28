# 업그레이드

같은 major 안의 업그레이드는 클러스터를 다시 만들지 않고 서버를 한 대씩 바꾼다. `0.1.3 → 0.1.4`와 `0.1.9 → 0.2.0`은 같은 절차다. major가 다른 서버끼리는 연결하지 않으므로, major 업그레이드는 그 major의 릴리스 설명을 따른다.

## 바뀌는 것과 바뀌지 않는 것

- 같은 major의 빌드는 Raft 로그·상태·서버 사이 통신(SFCP)·사용자 요청 형식을 서로 읽는다. 바꾸는 동안 버전이 섞인 클러스터도 그대로 동작한다.
- 새 빌드가 더한 동작은 **기능**(`network-transit-v1` 같은 이름)으로 알린다. 클러스터는 모든 서버가 가진 기능만 쓴다. 그래서 마지막 서버를 바꿀 때까지 새 기능은 쓰이지 않는다.
- 릴리스 설명에는 기능 집합의 변화와 버전 범위를 표로 적는다.

## 절차

1. `sfcli cluster status`로 클러스터가 건강한지 본다(리더가 있고 투표 서버가 모두 응답한다). 릴리스 설명에서 새 기능이 있는지 본다.
2. 새 기능이 있는 릴리스면 원할 때 백업을 받아 둔다.

   ```sh
   sfcli cluster backup create --out cluster-before-0.1.4.backup
   ```

3. 설치하기 전에 새 `sfcd` 바이너리로 각 서버에서 미리 돌려 본다(dry run). 서버에 저장된 control 상태의 사본을 새 빌드로 읽고 다시 적용해 보며, 서버는 그대로 돌아도 되고 아무것도 바뀌지 않는다. 사본은 임시 디렉터리에 만들었다가 지운다(`control/raft.db`, `control/fsm.db` 크기만큼의 공간이 필요하면 `--scratch DIR`).

   ```sh
   sudo ./sfcd-0.1.4 --config /etc/sfc/node.yaml upgrade-dry-run
   ```

   "can start on …"이면 다음으로 간다. "would not start on …"이면 그 빌드는 이 서버의 저장 상태를 읽지 못하니 설치하지 않는다(릴리스 문제로 알린다). 출력의 `(stage …)`는 어느 검사가 거절했는지다. 서버가 도는 동안 복사한 사본은 복사 중 쓰기로 드물게 깨질 수 있으니, 실패하면 그 서버의 sfcd를 멈추고 한 번 더 돌려 확인한다.
4. 서버 한 대씩 패키지를 바꾼다. 패키지는 돌고 있던 `sfed`·`sfcd`만 다시 시작한다. 컨테이너는 엔진이 다시 시작하는 동안에도 계속 돈다.

   ```sh
   sudo apt install ./sfcd_0.1.4_amd64.deb        # Debian·Ubuntu
   ```

   `sfcli node show <서버>`가 새 버전과 Ready를 보일 때까지 기다린 뒤 다음 서버로 간다. 리더는 마지막에 바꾼다. 리더인 `sfcd`는 멈추라는 신호(SIGTERM)를 받으면 다른 투표 서버에게 리더를 넘긴 뒤 멈추므로(최대 10초), 리더를 바꾸는 동안에도 쓰기가 오래 멈추지 않는다.
5. 바꾸는 동안 `sfcli cluster upgrade status`로 서버별 버전과 기능, 클러스터가 지금 쓸 수 있는 기능, 서버마다 모자란 기능을 본다.

   ```text
   Connected to jay2 (sfcd 0.1.4)
   Versions are mixed: 0.1.3 ×1, 0.1.4 ×2
   The cluster can use: network-transit-v1

   NODE  VERSION  FEATURES                                LACKS
   jay2  0.1.4    network-transit-v1,network-transit-v2   -
   jay3  0.1.4    network-transit-v1,network-transit-v2   -
   jay4  0.1.3    network-transit-v1                      network-transit-v2
   ```

6. 모든 서버를 바꾼 뒤 같은 명령에서 `LACKS`가 모두 `-`이고 섞인 버전 줄이 없는지 본다.

## 되돌리기

**새 기능이 있는 릴리스는 마지막 서버를 바꾸면 클러스터가 그 기능을 쓰기 시작한다. 그 기능을 쓴 기록이 하나라도 남으면, 그 기능을 모르는 빌드로는 돌아갈 수 없다.** 옛 빌드는 그런 기록을 만나면 상태를 잘못 바꾸지 않도록 멈춘다.

- 되돌릴 수 있는 때는 아직 옛 빌드인 서버가 하나라도 남아 있는 동안이다. 새 기능이 걱정되면 먼저 한 대만 바꾼 채로 써 보고, 문제가 없을 때 나머지를 바꾼다.
- 새 기능이 없는 릴리스는 언제든 옛 빌드로 되돌릴 수 있다.
- 꺼져 있는 서버도 교집합에 들어간다. 꺼진 옛 서버가 남아 있으면 클러스터는 새 기능을 쓰지 않는다.

## 서버 추가·백업과 버전

- 클러스터가 이미 쓰는 기능을 모르는 빌드는 가입할 수 없다(`version` 거부). 새 서버는 지금 클러스터와 같거나 더 새로운 빌드로 설치한다. 더 새로운 빌드는 가입할 수 있고, 다른 서버를 모두 바꿀 때까지 새 기능은 쓰이지 않는다.
- 백업·snapshot도 같다. 이 빌드가 모르는 기능을 쓴 백업은 복원하지 않는다.

## 문제가 생기면

| 보이는 것 | 뜻과 할 일 |
|---|---|
| sfcd 로그 "… Majors differ, so it is not connected" | 다른 major의 빌드를 설치했다. 같은 major의 빌드로 바꾼다 |
| `cluster upgrade status`의 `LACKS`가 마지막 서버를 바꾼 뒤에도 남음 | 그 서버가 아직 옛 빌드이거나 보고가 늦다. `sfcli node show <서버>`로 버전과 Ready를 본다 |
| 옛 빌드 서버가 "Raft entry uses a feature this build does not have"로 멈춤 | 클러스터가 이미 새 기능을 쓴다. 그 서버를 새 빌드로 올린다 |
| 요청이 "a cluster member does not have a feature this command uses"로 거절됨 | 아직 그 기능을 모르는 서버가 있다. `cluster upgrade status`로 막는 서버를 찾아 올린다 |
