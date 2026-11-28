# Raft에 쓰는 것과 SFCP로 보내는 것

Raft는 클러스터 자체를 유지하는 데만 쓴다. 모든 서버가 같은 값으로 합의해야 하는 것만 Raft에 쓰고, 계속 변하거나 잃어도 다시 만들 수 있는 것은 SFCP로 보내 받는 쪽 메모리에만 둔다.

- **Raft**: 구성원·키·권한·작업 공간, 앱·볼륨·네트워크의 원하는 상태와 소유, 주소 배정, 바뀐 사실(native ID, 적용·해제, 종료), 회수·닫힘 증명.
- **SFCP**: "아직 살아 있고 그대로다"라는 갱신, 단계 진행 상황, 측정값, 로그.
- 같은 값을 주기적으로 Raft에 다시 쓰지 않는다. 신선도가 필요한 판단은 그 명령에 붙은 서명된 최신 근거나, 만료 사건 한 번으로 한다.

## 노드 보고 method 분류

서버가 Raft에 쓰는 보고 method는 모두 아래 표의 한 칸에 속한다. 코드의 `internal/cluster/node_methods.go` `nodeMethods`(보고 항목)와 이 표가 다르면 `TestReportMethodsMatchR14Table`이 실패한다. 새 보고 method를 만들면 두 곳에 함께 적는다.

| 종류 | method (예) | 판정 |
|---|---|---|
| 사용자·운영자 명령 | `app-command`, `vault-approve-command`, `member-report` | Raft 유지. 원하는 상태와 구성원 자체다. |
| 한 번만 일어나야 하는 작업 기록 | `node-shell-report`, `standalone-policy-report`, `image-build-cache-automatic-report`, `image-build-automatic-git-report`, `image-build-cache-prune-report`, `image-build-job-report`, `image-build-owner-report`, `registry-maintenance-report`, `image-cache-report`, `tunnel-reconnect-report`, `compact-report`, `task-restart-report`, `tenant-retirement-report`, `route-retirement`, `route-dispatch`, `volume-backup-report`, `volume-archive-report`, `volume-archive-key-report`, `volume-restore-report`, `volume-delete-report`, `volume-file-report`, `volume-create-report`, `volume-move-report`, `checker-build-report`, `external-registry-closed`, `system-network-report`, `network-leave-report`, `virtual-bridge-closed`, `credential-store-report`, `vault-holder-report`, `vps-report` | Raft 유지. begin·complete·uncertain·회수 증명은 다른 서버가 이어받을 때 필요한 사실이다. 중간 진행률은 싣지 않는다. |
| 바뀐 사실 관찰 | `certificate-expiry-report`, `image-build-git-observation-report`, `network-dns-progress`, `node-storage-report`, `registry-report` | 사실이 바뀔 때만 Raft. git 관찰(`Same`)과 인증서 만료(만료된 것이 있을 때만)는 이미 그렇다. 앱 단계 관찰(`app-progress` observe)은 1단계(#432)에서 고쳤다. 10분 측정에서 이 칸의 쓰기는 0이었다. |
| 배포 단계 진행 | `app-progress`, `app-delivery-progress` | 결과 사실(native ID, 적용, 종료)은 Raft 유지. 한 단계만 바꾸는 보고는 그 단계 레코드로 CAS한다(3단계). |
| 이미 SFCP | 노드 보고(30초), 노드 관찰(30초), observability, 로그, 1단계 health 갱신 | 그대로. |
| 최신 읽기 | 권한·작업 확인 읽기(`Read(latest)`) | 상태는 바꾸지 않지만 읽을 때마다 Raft Barrier 항목을 하나 썼다. 2단계 첫 PR에서 ReadIndex로 바꾼다(아래). |
