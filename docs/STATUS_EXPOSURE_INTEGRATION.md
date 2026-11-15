# 初回ARTEX計画から証拠付き追加L1検査への接続

この変更は公開βでは既定無効のローカルARTEX経路を拡張する。所有確認済み対象の初回GET後、許可済みの固定特徴だけをARTEXに渡し、Apache系と観測された対象でARTEXが`mod_status`を提案し、追加GETへの明示同意が署名付き範囲と診断枠の両方にある場合だけ、Gatewayが固定`/server-status?auto`を最大1回許可する。Workerは応答本文を返さず、固定マーカーだけを報告する。検出判定はWorkerの実測結果と監査ハッシュから作り、ARTEXの候補を検出済みと扱わない。実サイトL2は禁止のまま。

| 処理ID | コード | 検証 |
|---|---|---|
| P09 | `aegis/artex_bridge.py` の固定カタログ、`AssessmentService._plan_with_artex` | `test_artex_bridge.py`、Linuxの実ARTEX overlayテスト |
| P10 | `AssessmentService._launch_guard`、`Gateway`、`status_marker_tool`、`workers/http_probe.py` | `test_status_marker_report.py`、`test_status_exposure_lab.py` |
| P11 | `AssessmentService._record_status_result_locked`、`analyze_status_marker_report` | `test_real_service.py`、3モードの独立ラボ |
| P12 | `_upsert_finding`、`snapshot` の結果表示データ | `TestStatusPlanToEvidence` |

## 同一ラボのローカル測定

`VULNIX_NO_ENV_LOCAL=1 python3 -m scripts.bench_status_exposure_after` の結果を[測定JSON](STATUS_EXPOSURE_COMPARISON_STANDIN.json)に保存した。対象は独立した`StatusExposureLab`の脆弱・修正済み・紛らわしいHTTP 200の3モード。変更前後とも同じ固定ラベルを使った。変更後の**ローカル測定はPython製ARTEX代役**であり、実モデルのトークン・待ち時間を表すものではない。

| 指標 | 変更前 | 変更後・代役 |
|---|---:|---:|
| TP / FP / FN / TN | 0 / 0 / 1 / 2 | 1 / 0 / 0 / 2 |
| Precision / Recall / 誤検知率 | 算出不可 / 0% / 0% | 100% / 100% / 0% |
| 完了時間・3モード | 0.074 / 0.096 / 0.094秒 | 0.669 / 0.664 / 0.656秒 |
| Gateway呼び出し / Worker起動 / 対象GET | 各1 | 各2 |
| 状態保存 / 署名台帳commit | 各15 / 17 | 各17 / 21 |
| 実モデル呼び出し / 有料API支出 | 0 / 0 | 0 / 0 |
| 失効・取消の拒否 | 2/2 | 2/2 |

状態保存と署名台帳commitはファイル永続化の呼び出し回数で、一般的なSQL DBのアクセス数ではない。変更後は検出能力と引き換えに待ち時間と処理回数が増えた。改善率として処理速度の向上を主張しない。

## 実ARTEX overlayとローカル模擬モデルのLinux測定

[CI run 43771848321](https://github.com/FORIFOR/Vulnix/actions/runs/43771848321)の同じ独立ラボで、実ARTEX overlayによる変更後経路を3モード実行した。[計測JSON](STATUS_EXPOSURE_COMPARISON_REAL_ARTEX.json)はCI成果物の`status-exposure-comparison.json`をそのまま保存したもの。各モードでARTEX計画→Gateway→Worker→証拠付き所見を確認し、TP1/FP0/FN0/TN2、Precision 100%、Recall 100%、誤検知率0%だった。これは3件の固定ラボに対する値であり、一般のWebサイト全体の精度ではない。

| モード | 固定L1 | 実ARTEX経路 | ローカルモデル通信 | Gateway推定トークン | Gateway / Worker | 状態保存 / 署名台帳commit |
|---|---:|---:|---:|---:|---:|---:|
| 脆弱 | 0.107秒 | 1.368秒 | 2回 | 8,328 | 各2回（変更前各1回） | 17 / 21（変更前15 / 17） |
| 修正済み | 0.204秒 | 1.220秒 | 2回 | 8,328 | 各2回（変更前各1回） | 17 / 21（変更前15 / 17） |
| 汎用200 | 0.107秒 | 1.321秒 | 2回 | 8,328 | 各2回（変更前各1回） | 17 / 21（変更前15 / 17） |

推定トークンはPlanner LLM Gatewayの予算計上値であり、モデルが返した実使用量ではない。モデルはローカル模擬サーバーで、実際の有料API支出は0。価格表に基づく商用モデル費用は未算定。停止・失効の拒否は変更前後とも2/2。診断時間・モデル通信・Worker起動・保存回数は増加したため、速度や費用が改善したとは評価しない。

## 公開前の不足

公開APIと画面には追加GETへの同意をまだ表示・保存していない。現行公開β設定ではARTEX自動計画も無効。実サイトへの新たな診断通信、本番反映、L2の有効化は行わない。UIの操作数・390px確認、Abliteration AIの日本語解説、実サイトの所有確認後E2Eは別に検証が必要。
