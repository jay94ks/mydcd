## 내장 Secret 값 복제 — VaultValue

`VaultValue=21`은 현재 voter 사이의 유한 stream이다. 형식은 `CertificateMaterial=17`과 같다. kind1 요청과 kind2 응답 모두 tag1에 JSON bytes, tag2에 tag1의 SHA-256(32B)을 담는다. Body 상한은 192KiB이고, 전송 owner 동시성은 4다. 사용자, Unix, relay, early data, datagram은 허용하지 않는다.

요청은 `{Schema:1, Replicate: BuiltinValue}`이다. `BuiltinValue`의 칸은 `{Schema:1, Cluster, Realm, Kind, Object, Revision, Keys, Write, Epoch, Receipt, Sealer, Sealed}`이고, `Sealed` 외의 칸은 모두 공개 칸이자 AAD다. 받는 쪽은 다음을 모두 확인한 뒤 값을 로컬 저장소에 동기 기록한다.

- 보낸 쪽과 자기 자신이 모두 현재 voter다.
- `Sealer`가 보낸 쪽이다.
- Raft의 그 write가 Dispatched나 Unknown이다.
- 공개 칸이 그 write의 원 요청·receipt와 같다.

같은 write에 이미 다른 값이 있으면 거부한다. 받는 쪽은 값을 열지 않는다. 응답은 `{Schema:1, Holder:{Voter, Signature}}`다. 서명 대상은 `HolderBytes`, 곧 `"sfc-secret-builtin-holder-1\0"`에 `{Cluster, Tenant, ID, Epoch, Revision, Object, Digest, Voter}`의 JSON을 붙인 바이트다. `Digest`는 BuiltinValue 전체 JSON의 SHA-256이다.

쓰는 voter는 자기를 포함한 voter 과반의 서명을 모은 뒤 `vault-observe-write`(Applied)에 `Reporter`, `Digest`, `Holders`를 담아 보낸다. 과반을 모으지 못하면 Unknown으로 남긴다. 이어서 같은 write의 recover가 같은 봉인 값으로 확인 모으기를 계속한다. 값, 봉인 값, 키는 Raft 명령, 이벤트, 공개 Reply에 넣지 않는다.

### 채워 받기

요청 `{Schema:1, Fetch:{Realm, Digest}}`는 현재 voter가 게시된 builtin revision의 봉인 값을 보유 voter에게 받아 갈 때 쓴다. 답하는 쪽은 자기와 묻는 쪽이 모두 현재 voter이고, 그 realm 트리의 보유 기록에 그 digest가 있을 때만 `{Schema:1, Value: BuiltinValue}`를 돌려준다. 받는 쪽은 digest와 공개 칸이 보유 기록과 같은지 확인하고 저장한다. 그다음 node 보고 `vault-holder-report`(`Realm, Kind, Object, Revision, Digest`에 서명)로 자기를 보유 voter에 더한다. reducer는 보고한 voter가 현재 voter인지 확인하고, 더는 voter가 아닌 보유자를 목록에서 뺀다.

voter마다 30초에 한 번 다음을 정리한다.

- 이제 아무도 읽지 않는 값은 로컬 저장소에서 지운다. 보유 기록에 없고, 아직 끝나지 않은 쓰기의 값도 아닌 값이다. 지울 값은 이번 정리를 시작하기 전에 저장된 값만이다. 정리하는 동안 복제되어 들어온 값(이미 보유 영수증에 서명한 값)은 다음 정리에서 최신 상태로 다시 판단한다.
- voter가 아니게 된 서버는 로컬 내장 vault의 값을 모두 지운다.

보유 기록 자체는 vault 기록이 바뀔 때마다 정리된다. 남는 것은 다음 셋뿐이다.

- secret의 현재 revision
- 보존된 사용 기록이 고정한 revision
- 그룹의 현재 검증값
