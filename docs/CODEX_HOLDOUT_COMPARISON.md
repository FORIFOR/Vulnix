# Codex版とClaude版の adaptive_holdout_v2 の比較（統合しません）

2026-11-19 JST。

**比較したもの**

| | 場所 | 状態 |
| --- | --- | --- |
| Codex版 | `/Users/shuhei/Projects/Vulnix-integration-readiness`（PR #85の作業ツリー）の `scripts/eval_adaptive_holdout.py`、`tests/fixtures/adaptive_holdout_v2/` | 未追跡のファイル |
| Claude版 | このブランチ（`claude/ai-value-eval`）の同名ファイル | — |

**作業の条件**

- Codex版のファイルは、読み取りと実行だけ行い、変更していません。実行は手元で一度だけ（`python3 -m scripts.eval_adaptive_holdout`）で、外部への送信はしていません。結果は一時ディレクトリに出力しました。
- 2つの版は、ファイルのパスが同じで、中身はまったく別物です。そのまま統合すると、片方がもう片方を上書きします。**直接は統合しません。**

## 1. データの比較

| 項目 | Codex版 | Claude版 |
| --- | --- | --- |
| SHA-256 `cases.json` | `c0da75d1…a02cb` | `288eee7c…77e32` |
| SHA-256 `truth.json` | `e5f8cc9a…0258` | `36cda80d…ae2f` |
| SHA-256 `owner_specs.json` | `bdd01796…547b` | `8aad30a9…f590` |
| 条件の数 | 60（5分類×12） | 60（5分類×12） |
| 検査が必要な条件 | 17 | 25組（条件と検査IDの組） |
| 正解の形 | 検査IDは1つ（`expected_catalog_id`） | 検査IDの集合（複数も可） |
| 所有者のメモ（自由記述） | なし | 28件 |
| 比較用の規則のハッシュ固定 | なし | `scripts/adaptive_baselines.py` のハッシュを manifest に記録 |
| 規則とラベルの作成順の記録 | なし | 自己申告で記録 |

## 2. 情報漏えいと評価の妥当性に関わる問題

### Codex版の問題

1. **観測値の名前に、判定がそのまま入っています。**
   - 例：`response_classification` の `protected_data_exposed`、`insufficient_role_200_with_leak`
   - 例：`cookie_purpose` の `session_missing_secure_httponly`、`csrf_token_missing_secure`
   - 例：`cors_shape` の `reflect_untrusted_with_credentials`、`vary_origin_missing_on_dynamic_cors`
   - 例：`status_endpoint_hint` の `cve_2021_41773_banner_candidate`

   これらは測定した事実ではなく、分析した結果の結論です。結論を入力として渡しているため、評価対象（モデルや規則）は判定をしなくても正解できます。
2. **AIを模擬するはずの規則Cが、AIを使わない規則のままF1 1.000になります。**
   - 実行結果：TP17 / FP0 / FN0、重大な見逃し3件
   - `contextual_mock_intents` は、上の判定入りの値で分岐する手書きの規則です。
   - つまり、このデータはAIを使わない規則で満点を取れます。「AIが固定ルールを上回るか」を測る目的には使えません。
3. **方式Dの要求に、元のケースID（`H001`〜`H060`）が分類ごとの順番のまま入っています。** 正解と直接は結び付きませんが、並び順から分類が分かってしまいます。
4. **漏えいの確認が不十分です。** 判定理由の文字列と2つの項目名が要求に含まれていないかを見ているだけです。値の名前に結論が入っていないかは確認していません。
5. **出力上限が足りないおそれがあります。** `max_tokens` が960で、60件分の回答に対して余裕がありません。回答の形は「選んだケースIDの一覧」だけで、どの検査を選んだかを受け取れません。
6. **比較用の規則がハッシュで固定されていません。** 規則とラベルの作成順を後から確かめる手段がありません。

### Claude版の問題（同じ基準で確認したもの）

1. 作成者が規則を書いた後に条件を作っています。Eが誤った条件は、作成者が意図して作ったものです（[監査 §1](ADAPTIVE_HOLDOUT_V2_AUDIT.md)）。
2. メモの有無と正解に相関があります（メモあり57%、メモなし28%）。
3. 方式Dの指示文に、データの設計を反映した助言（「メモは否定することもある」）が入っています。
4. ラベルは1人で付けており、独立した再判定はまだです。

## 3. 結論

- Codex版のデータと規則Cの結果（F1 1.000）は、AIの付加価値を測る根拠にしません。
- Codex版で役に立つ考え方は2つあります。
  - 「AIを呼ぶかどうか」を判定する部分を、独立した段階にしていること（`should_invoke_planner`）
  - 正解ラベルに「脆弱性があるか」を持たせ、検出の評価もしていること

  どちらも、Claude版に取り込む場合は改めて設計し、テストを書いてから入れます。ファイルを丸ごとコピーすることはしません。
- 統合の前に、所有者が「どちらのパスを残すか」を決める必要があります。PR #85の作業ツリーにあるCodex版の未追跡ファイルは、削除も移動もしていません。

## 4. 再確認（2026-11-19 夜）

Codex版の未コミットファイルは、変更されていないことを確認しました（更新時刻は 16:26〜16:30 のまま、今回も読み取りだけ）。

| ファイル | SHA-256 |
| --- | --- |
| `scripts/eval_adaptive_holdout.py` | `e3bb7e52f578f07c558334ad5ed8d90d4311b5d792648107a17c8120568df0d6` |
| `tests/fixtures/adaptive_holdout_v2/cases.json` | `c0da75d1a3fd907e9b21e53fee13fa989a401bddfb7e361c2ab3ac73f1ba02cb` |
| `tests/fixtures/adaptive_holdout_v2/truth.json` | `e5f8cc9a6e6d14b30c50aa554d319006a3a169fd0b3bcb32510dfc82cedc0258` |
| `tests/fixtures/adaptive_holdout_v2/owner_specs.json` | `bdd0179640b8e0e5c9cdd0174b73edd917f66d0b69f48aa4e8da9bb407df547b` |
| `tests/fixtures/adaptive_holdout_v2/manifest.json` | `8d0d9e249fa74a1414ca8a9d0b5a10592d5de198fe464610610751355d8ef363` |
| `tests/fixtures/adaptive_holdout_v2/README.md` | `9bdc27baef03719b6462e610f2e40181f9ebf4225481c27a6f6c808765017a4a` |

### Claude版にだけ追加したもの（Codex版には当てはまりません）

- 判定者に正解を見せずに再判定してもらうための資料と手順（[RELABEL_PROTOCOL](ADAPTIVE_HOLDOUT_V2_RELABEL_PROTOCOL.md)）
- 承認を受けて1回だけ実AIに送るための経路（`run_approved`）

### Codex版のデータに独立判定を行わない理由

Codex版では、観測値の名前に結論が入っています（§2）。このデータを判定者に渡しても、判定者は結論を読み取るだけになり、判断の確認になりません。
