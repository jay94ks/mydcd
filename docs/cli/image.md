# sfcli image: registry 안의 이미지

| 명령 | 하는 일 |
|---|---|
| `sfcli image list REGISTRY [REPOSITORY] [--external]` | REPOSITORY가 없으면 repository 목록, 있으면 그 안의 이미지(tag·digest·크기) |
| `sfcli image show IMAGE` | 이미지를 digest로 해석하고 platform과 신뢰 여부를 보여 준다 |
| `sfcli image resolve IMAGE` | digest로 고정한 이름(`name@sha256:...`)만 출력한다. 스크립트용 |
| `sfcli image pull-content IMAGE@DIGEST --kind manifest\|config\|layer [--digest D] [-O FILE]` | manifest, config, layer 하나를 받는다. 실패하면 만들던 파일을 지운다 |
| `sfcli image usages IMAGE` · `usages --source NAME` | 그 이미지(또는 외부 출처)를 쓰는 앱, 작업, 빌드 |
| `sfcli image delete REGISTRY REPOSITORY:TAG\|REPOSITORY@DIGEST [--external] [--dry-run]` | tag 하나나 digest 하나를 지운다. 앱이 쓰는 이미지는 지우지 않는다 |

`delete`는 이미지를 목록에서 지울 뿐 공간은 비우지 않는다. 공간은 `sfcli registry gc REGISTRY`가 비운다. 여러 이미지를 조건으로 지울 때는 `sfcli registry prune`을 쓴다.

```sh
sfcli image list shop-registry shop/web
sfcli image resolve registry.shop.test:5443/shop/web:latest
sfcli image delete shop-registry shop/web:old && sfcli registry gc shop-registry
```

`pull-content`는 터미널에 바이너리를 찍지 않는다. `-O FILE`(새 파일, 0600)이나 파이프로 받는다. 큰 layer는 `--timeout`을 늘린다.
