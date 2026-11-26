# mydc volume: 볼륨

볼륨은 앱 데이터를 한 서버에 담는다. 앱 볼륨의 이름은 `앱/볼륨`이고, `volume register`로 서버의 기존 디렉터리를 올린 작업 공간 볼륨은 `볼륨`만 쓴다. 작업 공간은 `--tenant`가 먼저고, 없으면 지금 context의 작업 공간을 쓴다.

## 보기

| 명령 | 하는 일 |
|---|---|
| `mydc volume list [--all]` | 작업 공간의 볼륨. `--all`은 모든 작업 공간(시스템 관리자) |
| `mydc volume show 앱/볼륨` | 한 볼륨의 서버, 상태, 예약 크기, 쓰는 서비스, 남은 옛 사본 |
| `mydc volume usage 앱/볼륨` | 서버가 지금 재어 본 실제 사용량 |
| `mydc volume users 앱/볼륨` | 이 볼륨을 쓰는 앱·서비스 |

`show`의 사용량은 서버가 주기적으로 잰 값이다. 값이 없으면 "모름"이지 0이 아니다. `usage`는 그 자리에서 한 번 더 잰다.

## 만들기와 지우기

```sh
mydc volume create shop/data --node node-a --uid 10001 --gid 10001
mydc volume delete shop/data
mydc volume register files --node node-a --storage disk1 --root-generation 1 --path /srv/files
mydc volume unregister files
```

- `create`: `--mode`(기본 0750), `--generation`(기본 1), `--size`(예약할 공간)를 더 받는다. UID와 GID는 0이 아닌 값을 직접 정한다.
- `delete`: 볼륨과 데이터를 지운다. 아직 만들어지는 중이면 만들기를 취소한다. 서비스가 쓰는 동안은 서버가 거절한다.
- `delete 앱/볼륨 --retained 이동ID`: 이동이 끝난 뒤 원래 서버에 남은 옛 사본만 지운다. 볼륨은 그대로다.
- `register`는 `mydc node storage`로 등록한 저장 위치 안의 디렉터리를 볼륨으로 올린다. 파일은 그 자리에 있고, `unregister`도 파일을 지우지 않는다.

**받음과 끝남은 다르다.** 서버가 변경을 받으면 `accepted`이고, 실제 서버에서 디렉터리를 만들거나 지우고 확인을 받아야 `done`이다. 명령은 끝날 때까지 기다리며 단계를 보여 준다. `--no-wait`이면 받은 뒤 바로 돌아오고, 나중에 `mydc op show ID`로 확인한다.

**generation**은 같은 이름의 볼륨을 몇 번째로 만들었는지다. 취소하거나 지운 generation은 다시 쓰지 않는다. 같은 이름을 다시 만들 때는 더 큰 `--generation`을 준다.

## 백업과 복원

```sh
mydc volume backup create shop/data --max-size 10GiB
mydc volume backup list shop/data
mydc volume backup show shop/data b-20261124-230000
mydc volume backup cancel shop/data b-20261124-230000
mydc volume backup delete shop/data b-20261124-230000
mydc volume restore shop/data b-20261124-230000 --to shop/data2 --max-size 10GiB
mydc volume restore list
mydc volume restore show r-20261125-010000
mydc volume restore cancel r-20261125-010000
```

- `backup create`는 `--name`(기본 `b-날짜-시각`, UTC), `--max-entries`(기본 100000)를 더 받는다. `--max-size`는 사본에 잡아 둘 공간이고 꼭 적어야 한다.
- 백업은 볼륨 파일을 그대로 묶은 사본이다. **DB 덤프가 아니다.** 볼륨을 쓰던 컨테이너가 정상으로 멈춘 상태여야 받는다(서버가 확인한다). 정상의 뜻은 이동과 같다. 종료 코드 0이거나, mydc가 보낸 정지 신호로 끝난 경우(SIGTERM이면 143)다.
- 복원은 **언제나 새 볼륨**(`--to`)에 한다. 원래 볼륨을 덮어쓰지 않는다. 새 볼륨은 백업과 같은 서버에 생기고, 앱의 app.yaml에서 새 이름을 가리키게 바꿔 배포해야 쓰인다. `--size`는 새 볼륨의 예약 크기이고 `--max-size`보다 작을 수 없다.
- 복원이 끝나면 파일이 확인된 상태다. 그 안의 DB가 정상으로 뜨는지는 앱을 띄워 봐야 안다.

## 공간 한도 (시스템 관리자)

```sh
mydc volume backup limits [--node node-a] [--all]
mydc volume backup limits set --node node-a --max-size 100GiB --max-backups 20 --staging-size 20GiB --staging-backups 2
mydc volume resize shop/data --size 20GiB
```

- 한 서버에서 백업이 쓸 공간은 클러스터 전체(`--all`) 한도와 작업 공간 한도가 둘 다 있어야 쓸 수 있다. 한도가 없으면 백업을 받지 않는다.
- `limits set`에서 빠진 옵션은 지금 값을 그대로 둔다. `--staging-*`은 진행 중인 백업·복원이 잠깐 쓰는 공간이다.
- `--volume-size`와 `--volumes`는 그 서버의 볼륨들이 예약할 공간과 개수를 묶는다. 한 번 정하면 없앨 수 없고 값만 바꿀 수 있다. 0은 새 예약을 막는다. 서버에 볼륨 예산이 생기면 그 서버의 `volume create`에는 `--size`가 꼭 있어야 하고, `--size`를 쓰려면 작업 공간 예산(`--tenant`)과 클러스터 예산(`--all`)이 둘 다 있어야 한다. 빠진 것이 있으면 CLI가 보내기 전에 알려 준다.
- `resize`는 볼륨의 예약 크기를 늘린다. 줄이지는 못한다. 예약은 클러스터가 세는 값이지 파일시스템 quota가 아니다.

## 다른 서버로 옮기기

```sh
mydc volume move shop/data -f app.yaml --max-size 10GiB --dry-run --save-plan move.json
mydc volume move --plan move.json
```

app.yaml에서 볼륨의 서버를 바꾼 뒤 `move`를 쓴다. 앱을 멈추고, 볼륨을 새 서버로 복사하고, app.yaml대로 다시 배포한다. 복사는 앱이 정상 종료했을 때만 시작한다. 정상 종료란 스스로 종료 코드 0으로 끝났거나, mydc가 보낸 정지 신호로 유예 시간 안에 끝난 경우다(예: SIGTERM이면 143). 유예가 지나 강제 종료(137)됐거나 OOM이면 복사하지 않는다. 옛 사본은 원래 서버에 남는다. 확인한 뒤 `volume delete 앱/볼륨 --retained 이동ID`로 지운다.

- `--dry-run --save-plan 파일`로 계획을 먼저 보고 저장한 뒤, `--plan 파일`로 바로 그 계획을 실행한다. 계획에는 끝나는 시각이 있고, 지나면 다시 만든다.
- 새 서버에 볼륨 예산이 있으면 볼륨의 예약 크기를 거기서 다시 잡는다. 작업 공간 한도와 클러스터 한도(`--all`) 중 하나라도 없으면 계획이 `TARGET_VOLUME_LIMIT_MISSING`, 남은 공간이나 개수가 모자라면 `TARGET_VOLUME_LIMIT_FULL`, 한도를 정한 뒤 서버 키가 바뀌었으면 `TARGET_VOLUME_LIMIT_OWNER_CHANGED`로 멈추고, CLI가 `volume backup limits --node 서버 set --volume-size … --volumes …`를 안내한다.
- 복사하는 동안 원래 서버의 백업 공간(`--max-size`, `--max-backups`)과 새 서버의 진행 중 공간(`--staging-size`, `--staging-backups`)도 이동 크기(`--max-size`)만큼 잡는다. 둘 다 작업 공간 한도와 클러스터 한도(`--all`)가 있어야 한다. 모자라면 계획이 `SOURCE_BACKUP_LIMIT_TENANT|_CLUSTER` 또는 `TARGET_STAGING_LIMIT_TENANT|_CLUSTER`로 멈춘다.
- `--transfer-timeout`(기본 15m, 1s–24h)은 복사가 걸려도 되는 가장 긴 시간이다. 늘려 주지 않는다.
- 계획의 `StoragePreflight`는 새 서버의 남은 공간을 잰 값이다. `State`는 `available`(충분), `insufficient`(모자람), `stale`(오래된 값), `unknown`(모름) 중 하나다. 모름을 0이나 충분으로 읽지 않는다. 이 값은 공간을 잡아 두지 않으며, 새 서버가 준비할 때 다시 확인한다.
- app.yaml이 Secret 그룹 승인을 더 요구하면 그 자리에서 비밀번호를 묻는다. 스크립트에서는 `--group-password-fd 영역/그룹=FD`(여러 번 가능)로 열린 파일 설명자에서 읽게 한다. 승인이 실패해도 받은 이동은 남고, `mydc op resume ID`로 이어 간다.
- 진행은 `mydc volume show 앱/볼륨`의 이동 단계로 본다.
- `mydc volume move cancel 앱/볼륨`은 새 서버가 넘겨받기 전의 이동을 멈춘다. 두 서버가 준비한 것을 지우고 볼륨은 원래 서버에 남는다. 취소는 아무것도 복사하지 않으므로, 앱이 강제 종료됐어도 끝난다. 복사를 시작하기 전에 계획이 끝나면 이동은 이어 갈 수 없다. 복사가 검증된 뒤에는 계획이 끝나도 새 서버에서 앱을 띄운다. `mydc op show`가 그렇게 알려 주면 취소하고 계획을 다시 만든다. 새 서버는 끝난 계획을 다시 시도하지 않는다.

## 파일 넣고 빼기

```sh
mydc volume files ls shop/data conf/
mydc volume files get shop/data conf/app.ini ./app.ini --max-size 1MiB
mydc volume files put shop/data ./app.ini conf/app.ini --overwrite
mydc volume files rm shop/data conf/old.ini
mydc volume files grant shop/data conf/ bob
mydc volume files revoke shop/data conf/ bob
mydc volume files grants [shop/data]
```

컨테이너 없이 파일 하나씩 옮긴다. 경로는 볼륨 안의 상대 경로이고 디렉터리는 `/`로 끝난다. 작업 공간 관리자가 아니면 그 디렉터리의 권한(`grant`)이 있어야 한다. 파일 내용은 작업 기록에 남지 않는다. 자세한 제약은 [볼륨 파일](../reference/volume-files.md)에 있다.

## 종료 코드

0 성공, 1 실패, 2 잘못된 명령줄, 3 서버가 거절했거나 실패로 끝남, 4 결과를 아직 모름(`mydc op show ID`로 확인).
