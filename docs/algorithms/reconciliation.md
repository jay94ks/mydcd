# Reconcile·참조·종료

## 목표와 실제 효과

Reconcile은 확정된 Desired를 현재 Applied·Pending·관측과 비교해 다음 실제 효과를 정한다. 공유 관리 상태는 실행 의도를 확정하고, 담당 노드의 journal은 원 효과와 내구 참조를 보존한다. Docker·커널·전송은 실제 어댑터가 수행한다.

```text
관리 Desired 확정 → 원 효과/참조 기록 → 실제 어댑터 실행
                                   → 결과·native 관측 → Applied/정산
```

관리 수락, 어댑터 반환, 실제 자원 종료는 각각 다른 사실이다. timeout 뒤 관측이 없다는 이유로 효과를 미실행 처리하거나 참조를 반환하지 않는다. 재개는 같은 원 효과·Task/native ID·세대와 저장된 입력을 따른다.

## 세대와 원 입력

새 목표를 적용할 때 원 resource identity·revision·generation·spec을 대조한다. 이전 작업의 늦은 응답은 다른 세대의 현재 효과를 확정할 수 없다. 변경 후보와 기존 consumer는 구분하며, 기존 consumer가 남은 drain은 그 참조의 종료를 기다린다.

## 참조와 종료

| 참조/자원 | 반환 전에 확인할 사실 |
|---|---|
| 앱의 관리 망·주소·DNS 참조 | 원 Task/consumer의 종료와 주소·query·flow 등 소비 정산 |
| Volume writer·mount·이관 참조 | 원 컨테이너/효과의 확실한 종료와 fence·전송 결과 |
| lifecycle source·compiled cache | 활성 사용·업로드·원 build job의 종료/참조 정산 |
| tenant/node 종료 | 소유 자원의 실제 종료·원 owner 보고·정책별 보존/해제 |

검사 pass는 컨테이너 Gone이나 Volume fence의 증거를 대신하지 않는다. 영수증 회수와 native 종료도 별개다. 양성 종료/결과가 확인될 때만 해당 내구 참조를 정산한다.

구현 경계는 [reconcile](../../internal/reconcile/), 상세 journal 계약은 개발 설계, 자원별 책임은 [자원표](../architecture/resource-ownership.md)를 따른다.
