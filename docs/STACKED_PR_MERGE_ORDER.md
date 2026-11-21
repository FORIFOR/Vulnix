# 重ねた PR（#97・#98・#99・PR-A）の統合順序と、base 変更時の CI 再確認

2026-11-21 時点。**main へのマージは所有者の判断で行います。** この文書は、その順序と、各段階で CI を確かめ直す手順をまとめたものです。

## 1. 今の重なり方

2026-11-21 に、統合の順序どおり一列に載せ直しました（各 PR の差分は、その PR のファイルだけです。載せ直しの前後でパッチが同一であることを `git range-diff` で確かめています）。

| PR | ブランチ | base | 先頭 |
| --- | --- | --- | --- |
| #97 診断ループ | `claude/diagnosis-loop-integration` | `main` | `9db3a83`（main の最新 `eb998fd` を含む） |
| #99 画面設計 | `claude/diagnosis-ui-design` | #97 | `0432704` |
| #100 PR-A 読み取り API | `claude/diagnosis-read-api` | #99 | `2c5e33c` |
| #98 評価の基盤 | `claude/diagnosis-eval-harness` | #100 | `39b2b28` |
| PR-B 画面 | `claude/diagnosis-ui-panel` | #98 | （PR-B） |

- CI（`.github/workflows/ci.yml`）は、`main` と `feat/**` に向けた PR と push でだけ自動で動きます。#97 に重ねた PR では自動で動かないため、`workflow_dispatch` で実行しています。
- 一列に重ねたので、ある PR の先頭での CI は、それより前の PR をすべて含んだ状態の確認になります。

## 2. 統合の順序（推奨）

1. **#97** を main へ。
2. **#99**（設計書だけ）。PR-A がこの設計を実装しているため、先に入れて文書のリンクを有効にします。
3. **PR-A**（読み取り API）。
4. **#98**（評価の基盤）。#97 以外とは独立しています。ただし、実モデルでの評価は、人による正解ラベルの確認と署名が終わるまで実行できません（コードで拒否します）。
5. **PR-B**（画面・読み取りだけ）。PR-A の API を使います。

PR-C（操作）は、PR-B の後に作ります。

## 3. base を変えるときの手順

#97 を main に入れた後、重ねた PR ごとに次を行います。

1. **マージの方法を確かめる。**
   - 通常のマージ（merge commit）の場合：`git rebase origin/main` で済みます。
   - squash の場合：前の PR の元のコミットが main に残らないため、`git rebase --onto origin/main <前の PR の先頭>` として、前の PR のコミットを除いて載せ直します（#99 なら `9db3a83`、#100 なら `0432704`、#98 なら `2c5e33c`）。
2. **base を main に変える。** `gh pr edit <番号> --base main`。#97 のブランチを消すと GitHub が自動で変えますが、**base の変更だけでは CI は動きません**（`pull_request` の既定の契機は opened・synchronize・reopened です）。
3. **載せ直したブランチを push する。** これが `synchronize` になり、main 向けの PR として3ジョブが自動で動きます。push しない場合は `gh workflow run ci.yml --ref <ブランチ>` で実行します。
4. **確かめる対象のコミットを固定する。** `gh pr checks <番号>` に加え、`gh api repos/FORIFOR/Vulnix/commits/<SHA>/check-runs` で、**今の先頭の SHA** で3ジョブ（Python 全件＋Linux 隔離、実 ARTEX、Web）がすべて成功していることを確かめます。古い SHA の成功は数えません。
5. **重ねた PR どうしの統合を確かめる。** 2つ目以降を入れる前に、main に入った内容の上で、次の PR を載せ直して3ジョブを再実行します（#98 と PR-A は別のファイルですが、`tests/` 全体を一緒に実行するのはこの時点が初めてです）。
6. **中断と失敗を分ける。** ジョブが失敗したら、テストの失敗、時間切れ、ランナーの中断（exit 143、ログなし、割り当て待ち）を分けて記録し、中断のときだけ再実行します。テストの失敗は原因を調べて直します。

## 4. 各段階で変えないこと

- テストの削除、しきい値の緩和、常に成功するスクリプトで、CI を通しません。
- ARTEX の overlay を変えた場合は、実 ARTEX のジョブの成功を必須にします（今回の4つの PR は overlay を変えていません）。
