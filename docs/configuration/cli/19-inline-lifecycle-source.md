## inline lifecycle source 준비

inline source의 staging/등록은 app 배포의 native/runner 성공과 구분한다. 담당 노드의 live lifecycle capability·정책/source 준비를 preflight에서 확인하며, 없으면 새 배포를 거부한다. 지원 노드에서는 같은 Task/Binding으로 Yaegi 또는 compiled CLI를 실행한다.

```sh
mydc compose up --operation deploy-one -f app.yaml
mydc compose resume --operation deploy-one
# 이미 시도한 source가 서버에서 확실히 missing일 때만 명시 재전송
mydc compose resume --operation deploy-one --retry-source
# 준비를 실행하지 않고 보존 문서/SourceFact로 계획만 조회
mydc compose plan --source-operation deploy-one
mydc compose diff --source-operation deploy-one
```

원 입력/옵션/provider는 source 전송 전에 private 기록에 고정한다. 일반 반복 up은 변경/삭제된 파일을 다시 읽지 않고 원 결과만 확인한다. plan/diff의 --source-operation은 새 -f/배치 옵션과 함께 사용할 수 없다. source-stored는 cache의 서명 사실이며 app 수락/Healthy가 아니다.

