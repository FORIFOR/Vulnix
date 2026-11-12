# AI アドバイザー（Abliteration AI 連携）設計 — 第1段階：模擬サーバーのみ

## 目的
診断の所見をもとに、AI に次の3つを作らせます。
- リスクの説明
- 修正の提案
- 次に調べる項目の提案

AI の役割は提案だけです。何かを実行するには、これまでどおり Vulnix の承認ゲートを通す必要があります。

## 構成
| 部品 | 役割 |
|---|---|
| `aegis/ai_advisor.py` | 送信データの組み立て（許可リスト方式）、出力の検証、アダプター `AbliterationAdvisor` |
| `aegis/abliteration_server.py` | 既存の模擬サーバーに「助言モード」を追加。システムプロンプトの印 `vulnix-advisor/v1` で切り替える |
| `AssessmentService.advise_findings(advisor)` | 実サービスの所見を除いてアドバイザーに渡し、監査ログに `advisor.asked` を記録する |

## AI に送るもの（許可リスト）
所見は、1件ずつ次の項目だけで組み立て直します。所見の dict をそのまま写すことはありません。

| 項目 | 内容 |
|---|---|
| `ref` | `F1`, `F2` などの不透明な参照。所見の ID は送らない |
| `rule` | 既知の規則 ID。それ以外は `other` |
| `category` | 既知の分類名。それ以外は `その他` |
| `severity` / `verdict` / `verdict_basis` | 列挙値。範囲外の値は既定値にする |
| `cve` | `CVE-YYYY-NNNN` の形のものだけ（最大5件） |
| `risk_score` | 0〜100 の整数 |
| `kev` | 真偽値 |

送らないものは次のとおりです。
- タイトル、概要、検出理由。観測値が埋め込まれていることがあるためです（例: ACAO のオリジン、TLS のバージョン）。
- 証拠（evidence）、URL、ホスト名、ヘッダー、Cookie、トークン、レスポンス本文
- 所有確認のトークン、資産の情報

組み立てた送信データは送る直前にもう一度検査し、URL、ホスト名、IP、メールアドレス、JWT、資格情報の値に見えるものが残っていれば、送信を拒否します。

実サービスの所見と、出どころが不明な所見は、アドバイザーに渡しません。判定には、既存の `_finding_touches_real_service` の許可リストを使います。

## AI から受け取るもの（構造化 JSON の検証）
```json
{"advice": [{"ref": "F1", "risk_explanation": "...", "remediation": ["..."],
             "next_checks": [{"title": "...", "level": "L1|L2", "reason": "..."}]}]}
```
形が合わないもの、危ないものは、項目ごとに捨てます。捨てた理由は `rejected` に残します。

| 理由 | 例 |
|---|---|
| `schema` | 形が違う、長すぎる、制御文字、件数が上限を超える |
| `authority_key` | `approved`、`token`、`tool`、`args` などの権限に関わるキー |
| `unknown_key` | 決めていないキー（モデルが付けた `status` も含む） |
| `unknown_ref` / `duplicate_ref` | 送っていない参照、重複した参照 |
| `leak` | 文章に URL、ホスト名、IP、パスなどが含まれる |
| `overclaim` | 判定が detected の所見を「実証済み」「悪用に成功」などと書く |
| `misproposal` | 破壊的な操作、高負荷・DoS、本番データや他の利用者への影響、承認の省略、スコープの拡大、攻撃ツールやコマンドの利用 |

## Worker を起動できない理由
- `ai_advisor.py` は、gateway、authz、runtime、workers、assessment などを import しません。テストで構文木を調べて確かめています。
- 「次の確認項目」には tool / action / args / target_id がありません。そのため `sanitize_proposal` に渡すと拒否されます。
- `status: "proposal_only"` と `required_gates` は、モデルではなくコードが付けます。
  - L1 の項目: 所有確認、範囲の承認
  - L2 の項目: さらに、人による L2 承認
- `advise_findings` は Gateway を呼びません。テストで呼び出しが0件であることを確かめています。

## 第1段階の制限
- 接続先はループバックだけです。`https://` の外部ホストも拒否します。
- API キーは受け取らず、`Authorization` ヘッダーも送りません。

## まだ作っていないもの
- 実際の Abliteration AI API への接続。API キーの扱い、課金、データの取り扱いの合意が必要で、利用者が判断することです。
- UI での表示と、サーバーの API エンドポイント
- 実際のモデルの出力品質の評価。今は模擬サーバーの決まった応答で、検証器を確かめているだけです。
- 判定の検出規則（`misproposal` など）は正規表現による保守的なもので、言い換えには漏れがあります。逆に、妥当な提案を捨てることもあります。
