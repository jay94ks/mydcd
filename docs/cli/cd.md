# sfcli cd: Git 브랜치에서 앱 배포하기

앱 하나에 CD 정책을 두면 서버가 Git 브랜치를 주기적으로 확인한다. 새 커밋은 후보(candidate)가 되고, `sync: manual`이면 사람이 승인해야, `sync: auto`이면 바로 배포된다. 정책은 app.yaml의 `x-sfc.cd`에만 둔다(아래). 따로 정책을 넣는 명령은 없다.

모든 명령은 작업 공간이 필요하다(`--tenant` 또는 context의 작업 공간).

| 명령 | 하는 일 |
|---|---|
| `sfcli cd show APP [-o yaml]` | 정책, 지금 후보, 실행 중인 커밋을 보여 준다. `-o yaml`의 `policy`는 app.yaml에 그대로 넣을 수 있는 `x-sfc.cd` 블록이다 |
| `sfcli cd sync APP [--candidate DIGEST] [--recover]` | 지금 후보를 바로 배포한다. `--recover`는 실패한 배포 위에 다시 배포한다 |
| `sfcli cd approve APP [CANDIDATE]` | 후보를 승인한다. CANDIDATE를 주면 본 후보와 같을 때만 승인한다 |
| `sfcli cd approve APP [CANDIDATE] --secrets [--operation ID]` | 배포가 기다리는 Secret Group 승인을 준다. 비밀번호는 터미널에서 묻는다. 스크립트는 `--group-password-fd REALM/GROUP=FD`로 열린 파일 서술자에서 읽게 한다 |
| `sfcli cd reject APP [CANDIDATE]` | 후보를 거절한다 |
| `sfcli cd approver-add APP USER` · `approver-remove APP USER` | 이 앱 후보의 승인·거절만 할 수 있는 사람을 더하거나 뺀다(USER는 작업 공간 구성원의 username). 승인자는 작업 공간을 읽을 수 있어야 하고, sync·pause·다른 앱은 할 수 없다. 더하고 빼는 것은 ManageCD가 있는 사람만 한다 |
| `sfcli cd pause APP` · `resume APP` | 브랜치 확인과 자동 배포를 멈추거나 다시 시작한다 |
| `sfcli cd abandon APP` | 끝날 수 없는 배포를 포기한다 |
| `sfcli cd replan APP` | CD 밖에서 앱이 바뀌었을 때(볼륨 이동 취소 등) 지금 후보를 다시 계획한다. 배포하지는 않는다 |
| `sfcli cd history APP` | 계획하고 배포한 커밋을 최근 것부터 보여 준다 |
| `sfcli cd diff APP` | 후보가 실행 중인 것과 비교해 무엇을 바꾸는지 서비스·경로·동작으로 보여 준다 |
| `sfcli cd override APP FIELD VALUE` | FIELD를 Git 값 대신 VALUE로 고정한다 |
| `sfcli cd release APP FIELD` | 고정을 풀고 다시 Git 값을 따른다 |
| `sfcli cd field APP FIELD` | FIELD의 Git 값, 지금 값, 고정 값을 보여 준다 |
| `sfcli cd put-local APP -f app.yaml [--id ID]` | 로컬 서비스(Git에 없는 서비스)를 app.yaml로 올린다. 큰 파일은 `ID-up`, `ID-p000`… 단계로 나눠 보낸다 |
| `sfcli cd clear-local APP [--id ID]` | put-local로 올린 서비스를 다음 sync 때 지운다 |

FIELD는 `services/SERVICE/FIELD[/KEY]` 모양이다. 예: `services/web/environment/LOG_LEVEL`. VALUE는 JSON이고, JSON이 아닌 단어는 문자열로 읽는다.

바꾸는 명령은 모두 `--id ID`와 `--if-revision N`을 받는다. `--if-revision`을 주지 않으면 명령이 방금 읽은 앱 상태가 그대로일 때만 바꾼다. 같은 `--id`로 다시 실행하면 지금 상태를 다시 읽지 않고 저장해 둔 같은 요청을 이어 보낸다([op](op.md)). 이미 결과가 있으면 그 결과를 보여 준다. `put-local`과 `clear-local`의 `--id`는 50자 이하다(주지 않으면 새 ID를 만들어 알려 준다).

## app.yaml `x-sfc.cd`

```yaml
x-sfc:
  cd:
    repository: https://git.example/team/shop.git
    branch: main
    path: app.yaml          # 저장소 안의 app.yaml 경로
    credential: git-readonly  # 선택. 비공개 저장소를 읽을 서버 자격 이름
    poll: 1m                # 선택. 1s~24h, 초 단위. 기본 1m
    sync: manual            # manual(기본) | auto
    drift: report           # report(기본): Git 밖에서 바뀐 것을 보여 줌 | reconcile: 되돌림
    prune: false            # true면 파일에서 사라진 서비스를 지운다
```

`repository`, `branch`, `path`는 꼭 써야 한다(없거나 값이 틀리면 `INVALID_CD`). 모르는 키가 있으면 `INVALID_FIELD`로 거부한다. 가져오기 제한(30초, 4MiB)과 대기열 한도는 지금 정할 수 있는 값이 하나뿐이라 블록에 두지 않는다.

CD는 `sfcli app deploy`로 켜고 바꾼다.

- CD가 없는 앱에 `x-sfc.cd`가 있는 파일을 배포하면 그 파일이 첫 실행이 되고, 그 뒤로 Git 브랜치를 따라간다.
- CD가 켜진 앱에 `x-sfc.cd`가 있는 파일을 배포하면 정책만 바뀐다. 서비스는 계속 Git에서 오고, 이 파일의 서비스는 쓰지 않는다(`app diff`·`app deploy`가 처음에 알려 준다). 기다리던 후보는 버리고 새 정책으로 다시 가져온다.
- CD가 켜진 앱에 `x-sfc.cd`가 없는 파일을 배포하면 CD가 꺼지고 그 파일이 보통 배포로 올라간다. `app diff`·`app deploy`가 맨 위에 "CD off" 경고를 내고, `app deploy`는 확인을 묻는다. 터미널이 없으면(`SFC_NONINTERACTIVE=1` 포함) `--force` 없이는 거절한다.
- Git 쪽 파일에 `x-sfc.cd`가 있으면 등록된 정책과 같아야 한다. 다르면 그 커밋을 후보로 받지 않는다(Git 커밋으로는 정책이 바뀌지 않는다).
- 서비스 없이 `name`과 `x-sfc.cd`만 있는 파일도 배포할 수 있다. 서비스는 Git에서 온다.
