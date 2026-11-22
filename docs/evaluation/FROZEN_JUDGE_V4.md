# v4 の評価のために凍結した判定器（案2を含む）

2026-11-22。新しい未見セット v4 は、この表のファイルを凍結した**後**に作り、**1回だけ**評価します。v4 の結果を見て、これらのファイルを1つでも変えた場合は、v4 を開発用に移し、新しい未見セットで評価し直します。`tests/evaluation/test_frozen_judge_v4.py` が、表とファイルの一致を確かめます。

## 凍結したファイル（SHA-256）

| ファイル | SHA-256 |
| --- | --- |
| `aegis/diagnosis_judge.py` | `7f477a97f9b65c86267fd2f66ff1d213f72c02548db5d094b3ce61371e7c8830` |
| `aegis/evidence.py` | `0ac25b893d16159bb923c7f272450be0e9486b034247b2f4d1346e36e74386f1` |
| `aegis/workers/reproduction_probe.py` | `2602c97f5ba5e682ffc0254d96cecb65554d30c4518b126fc60fc5e12a90075d` |
| `aegis/diagnosis_loop.py` | `d973a752f8c744de6e466f8b822994c2887153f96d8186e8db7da51547f72de5` |
| `aegis/adaptive_plan_runner.py` | `1dca57a756dfadc1f1be94de3e5efb05a53217c8ba49e578767c5fe482c31bb1` |
| `aegis/evaluation/metrics.py` | `aa6020892ef26babbc91fada12ced6bee516e0cc6b1ba863e58a53d3fbf6dd9b` |
| `docs/evaluation/EVALUATION_PROTOCOL.md` | `98fbe21e553da3be6228cbb0fc7764164a9ec5967ffb0c9254e4cf9b504bb549` |

## この凍結に含まれる規則と閾値（上のファイルの中で決まっています）

- **正規化**（`aegis/evidence.normalised_texts`）：次の表記の違いを元に戻してから照合します。
  - 大文字と小文字
  - HTML の実体参照
  - `%` エスケープ
  - JSON のエスケープ
  - JavaScript の `\uXXXX`
  - `\xHH`
  - 識別子は、単独で現れる場合だけ一致とします（`_has_token`）。
- **「成立」**（案2、`owner_record_read_by_other_account`）：次のすべてを満たす場合だけです。
  - A の固定の要求で、B の対照が成立し、本文を最後まで保持している。
  - 1つのオブジェクトが、資源 ID と目印を**欄の値として丸ごと**持つ。
  - ID の欄が B の資源を指す。
  - 所有者の欄（入れ子も含む）が B だけを指す。
  - HTML とテキストの場合は、A を名乗っていない。
- **「不成立」**（案1・案3）：次のすべてを満たす場合だけです。
  - 拒否だけからなる JSON（値はすべて200文字以内のスカラー値）であるか、ログインのフォームだけ・拒否の見出しだけの HTML（フォーム以外の表示が300文字以内）である。
  - B の識別子も名前もない。
- **本文の上限**：L2 の Worker が保持するのは4096文字までで、`response_truncated` を記録します。L1 の GET が読むのは4096バイトまでです。
- **採点**（`aegis/evaluation/metrics.py`）：次を数えます。
  - 6つの排他的な結果
  - TP・FP・FN・TN、適合率、再現率、特異度
  - Wilson の95%信頼区間

## 凍結に含まないもの

v4 のケースを読み込むための配線（`aegis/evaluation/evaluation_runner.py` の `LABEL_FILES`、`scripts/run_model_evaluation.py` の `--set`）は、判定に関わらないため、凍結の後に加えます。
