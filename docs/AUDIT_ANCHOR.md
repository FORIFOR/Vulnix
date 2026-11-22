# ローカル監査アンカー（Gate G 案 A）

監査ログ（`audit.jsonl`）は SHA-256 のハッシュチェーンです。途中の記録を書き換えると検出できますが、
**後ろの記録を消して古い状態に戻す（巻き戻す）と、残った部分はそのまま正しいチェーンに見えます**。
有料送信の予約ファイル（`audit.jsonl.advisor-budget`）による既存の確認も、サービスの OS ユーザーが
両方のファイルを書けるため、2つを揃えて古い状態に戻されると検知できません。

ローカル監査アンカーは、**サービスとは別の OS ユーザー**で動く小さな補助プロセスです。
監査チェーンの先頭（何件目まで・その記録のハッシュ）を、サービスが書けない追記専用ファイルに残します。
サービスは Unix ソケット経由で「記録して」「今の先頭は？」と頼むことしかできません。

実装: `aegis/audit_anchor.py`（補助プロセスとクライアント）、`aegis/audit.py`（照合と記録）。

## 守れるもの・守れないもの

守れるもの（サービスの OS ユーザーの権限を奪われた場合を含む）

- 監査ログの途中の改ざん（従来どおりチェーンで検出）
- 監査ログを古い正しい状態まで切り詰める巻き戻し
- 監査ログと予約ファイルを**両方とも**揃えて古い状態に戻す巻き戻し
- 記録済みの位置以降を別の内容で作り直すこと（fork）
- アンカーの記録ファイル自体の改ざん（補助プロセスが自分のチェーンを検証し、壊れていれば応答を拒否）

守れないもの

- **root の侵害**、または補助プロセスの OS ユーザーとして動ける攻撃者
- 最後に照合した位置より後ろにある、照合対象外の記録（下の「重要な記録」以外）だけを消すこと。
  次の重要な記録の直前に、その時点の先頭まで照合・記録します。
- 新しい記録の追記（サービスは記録を追加できる立場です。偽の記録を足すことは防げません）
- 初めて有効にしたときの状態（その時点のログを正しいものとして記録を始めます）
- **プラットフォーム全体のファイル**: `platform-audit.jsonl`（組織横断のアカウント操作の記録）と
  `platform-advisor-spend.json`（全組織合計の有料送信額）は対象外です。後者を巻き戻すと、
  プラットフォーム全体の上限に対する使用額を少なく見せられます（組織ごとの上限は守られます）。
  状態表示・レポートにも「対象外」と書いています。対象にするには別の変更が必要です。
- 補助プロセスが同じ OS ユーザーで動いている場合（開発・テスト）。動作はしますが「保護なし（same_user）」と表示します。

## 重要な記録（照合してから書き、書いた後に記録する）

`aegis/audit.py` の `ANCHORED_EVENTS` / `ANCHORED_PREFIXES`:

| 記録 | 意味 |
|---|---|
| `allow` | Gateway が Worker の実行を許可する |
| `planner_llm.forwarding` | Planner LLM への（有料の）送信 |
| `advisor.safe_send_requested` | AI 解説の外部（有料）送信の予約 |
| `result` | Worker の結果。所見の判定と証拠（`audit_hash`）はこの記録から作られる |
| `approval.approved` | L2 の承認 |
| `artex.item_approved` | ARTEX 計画項目（L2）の承認 |
| `diagnosis.*` | 診断ループの状態変更（`_diagnosis_journal` を通るものすべて） |

所見の判定（verdict）には独自の監査イベントがなく、`result` 記録から作られるため `result` で守ります。

各記録について、監査ファイルの排他ロックを持ったまま次を行います。

1. ログ全体のチェーンを検証し、アンカーの先頭を取得する。
   `件数 >= 先頭の位置` かつ `その位置の記録のハッシュ == 先頭のハッシュ` でなければ拒否。
   このプロセスが以前に見た位置より先頭が後退していても拒否（`anchor_regressed`）。
2. 記録を追記する。
3. 新しい先頭をアンカーに記録する。失敗したら呼び出し元にはエラーを返す
   （記録はディスクに残りますが、呼び出し元は変更を適用しません）。

有料送信では、予約ファイルを書き換える**前に**照合します（拒否された送信が予算を消費しないように）。
重要でない記録は従来どおり追記するだけです（アンカーに接続しません）。

## 失敗したときの動き（fail closed）

エラーは `AnchorError`（`ValueError` の派生）です。既存の「監査に書けなければ変更しない」経路がそのまま効きます。

- Worker は起動しません（`allow` が書けない）。
- 有料送信は行いません。
- 診断ループの状態は変わりません（`DiagnosisState._commit` は監査が先）。
- 所見の判定は付きません（`result` が書けないため、その実行は失敗扱い）。
- L2 の承認は「承認済み」になりません（承認の記録を先に書くように変更しました。却下と緊急停止の順序は従来どおり）。
- 重要でない記録（ログイン、拒否の記録など）は引き続き書けます。

起動時と状態表示（2秒ごと）では**照合だけ**を行い、記録はしません。
アンカーへの記録に失敗した重要な記録（呼び出し元には失敗として返したもの）を、後から状態表示が
こっそり記録することはありません。次の重要な記録が、その時点の先頭を記録します。

起動時にも照合します。失敗してもサーバーは止めず、状態に理由を表示し、上の操作を拒否し続けます
（各操作が毎回照合し直すため、補助プロセスが一時的に止まっていただけなら、戻れば再開します。
巻き戻しや書き換えは、ログを直さない限り拒否が続きます）。

## 記録元の識別と、すり替えへの対策

- 記録元 ID は `<VULNIX_AUDIT_ANCHOR_SOURCE>:<データルートからの相対パス>`（例 `prod:orgs/org_x/audit.jsonl`）。
  データルートはサーバーの `--data-dir` で、パスは解決（resolve）しません。
  別の場所の古いコピーへのシンボリックリンクや、ディレクトリの付け替えで「新しい記録元」に見せかけることはできません。
- データルートから監査ログまでのどこかがシンボリックリンクなら拒否します（`symlink`）。ログは `O_NOFOLLOW` で読みます。
- 補助プロセスは起動時に `--allow-source NAME`（複数可）で登録した名前の記録元だけを受け付けます（`unregistered_source`）。
- 接続ごとにソケットの相手の OS ユーザーを確認します（Linux `SO_PEERCRED`、macOS `LOCAL_PEERCRED`）。
  `VULNIX_AUDIT_ANCHOR_UID` と違えば拒否（`anchor_peer_mismatch`）、確認できなければ拒否（`anchor_peer_unverified`）。
  サービスと同じユーザーなら動作はしますが、保護とは表示しません（`same_user`）。
- `VULNIX_AUDIT_ANCHOR_*` は `.env.local` からは読みません（サービスのユーザーが書けるファイルのため）。
  運用者が systemd などの実環境で設定します。`SOCKET` だけあって `UID` / `SOURCE` が欠けていれば、重要な記録をすべて拒否します（`anchor_misconfigured`）。

## 状態表示

スナップショットの `audit_anchor`:

```json
{"enabled": true, "protected": true, "last_seq": 42, "error": null}
```

- `enabled`: `VULNIX_AUDIT_ANCHOR_SOCKET` が設定されている
- `protected`: 有効で、直近（2秒以内）の照合が成功し、かつ相手が**サービスとは別の OS ユーザー**だと確認できた。
  **これが true のときだけ「保護あり」と表示します**
- `last_seq`: 照合・記録できた最新の位置
- `error`: `chain_invalid` / `rollback` / `fork` / `symlink` / `same_user` / `anchor_regressed` /
  `anchor_unavailable` / `anchor_peer_mismatch` / `anchor_misconfigured` / `anchor_unregistered_source` /
  `anchor_corrupt` / `anchor_store_unwritable` などの短い理由

レポート（「監査チェーン検証」）と Web UI の監査ログ画面に1行で表示します。
無効のときは「監査ログと予約ファイルを両方とも古い状態へ戻された場合は検知できません」と明記します。

## 動かし方

無効（既定）: `VULNIX_AUDIT_ANCHOR_SOCKET` を設定しない。動作は従来と同じです。

有効にする例（Linux、systemd などで root が準備する）:

```sh
useradd --system --no-create-home --shell /usr/sbin/nologin vulnix-anchor
install -d -o root -g root -m 0755 /opt/vulnix-anchor
install -o root -g root -m 0644 aegis/audit_anchor.py /opt/vulnix-anchor/audit_anchor.py   # 標準ライブラリのみ
install -d -o vulnix-anchor -g vulnix-anchor -m 0700 /var/lib/vulnix-anchor               # 記録ファイル（0600）
install -d -o vulnix-anchor -g vulnix -m 0750 /run/vulnix-anchor                          # vulnix = サービスのグループ

# 補助プロセス（vulnix-anchor ユーザーで常駐）
sudo -u vulnix-anchor python3 /opt/vulnix-anchor/audit_anchor.py serve \
  --dir /var/lib/vulnix-anchor --socket /run/vulnix-anchor/anchor.sock --socket-mode 666 \
  --allow-source prod

# サービス側（3つとも必須。.env.local には書かない）
VULNIX_AUDIT_ANCHOR_SOCKET=/run/vulnix-anchor/anchor.sock \
VULNIX_AUDIT_ANCHOR_UID="$(id -u vulnix-anchor)" \
VULNIX_AUDIT_ANCHOR_SOURCE=prod \
python3 -m aegis.server --data-dir /var/lib/vulnix ...
```

- ソケットへの接続権は、ソケットを置くディレクトリのグループ（上の例では `vulnix`）で絞ります。
  代わりに `--socket-group GROUP --socket-mode 660` でソケット自体のグループを指定することもできます
  （補助プロセスのユーザーがそのグループに属している必要があります）。
- 補助プロセスは、記録ディレクトリ・ファイルが自分の所有でない、または他者が書ける権限になっていると起動を拒否します。
- 1つの補助プロセスで複数の組織（データディレクトリ）を扱えます。区別は上の記録元 ID です。
  ID をデータディレクトリ内のファイルに置かないのは、サービス側が ID ファイルごと作り直すと
  「新しい記録元」に見せかけられてしまうためです。
- データディレクトリを意図して作り直した場合は、補助プロセスのユーザーで
  `audit_anchor.py reset --dir /var/lib/vulnix-anchor --source <ID>` を実行します（ソケットからは実行できません）。
- `audit_anchor.py verify --dir ...` で記録ファイルの検証と各記録元の先頭を表示します。

## 検証

- `tests/test_audit_anchor.py`（同じ OS ユーザー、補助プロセスはスレッドで実行）
- Linux CI の「Local audit anchor as a separate OS user」ステップ（`scripts/audit_anchor_ci.py`）:
  別ユーザーの補助プロセスに対して、サービスのユーザーがソケット経由で記録・照合できること（相手のユーザーも確認）、
  記録ディレクトリとファイルを読み書きできないこと、2ファイル揃えた巻き戻しとシンボリックリンクによるすり替えを
  検知することを確認します。
  前提が欠けていればスキップせず失敗します。
