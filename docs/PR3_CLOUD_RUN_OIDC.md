# PR3: Cloud Run OIDC 所有確認の最小設計

## 信頼境界

Cloud Run の OIDC ID トークンはサービスアカウントの主体を示すが、それだけでは任意のホストの管理権限を示さない。所有確認には、管理者があらかじめ組織と登録済み HTTPS 443 ホストに紐付けたサービスアカウント sub と、そのホストの公開 head に置かれた短命の challenge の両方を要求する。

aegis/cloud_run_ownership.py はその判定の最小部品であり、診断権限を付与する API ルートには接続していない。署名を検証済みの claims を返す OIDC verifier と、組織ごとの登録済み主体を返す関数だけを信頼する。生の claims を呼び出し元から直接受け取らない。

## 手順

1. 認証済み依頼者が、組織と登録済みホストに対して challenge を発行する。サーバーは依頼者、組織、ホスト、登録済み主体、OIDC audience、有効期限を一緒に保持する。有効期限は5分。
2. Cloud Run 側は指定された audience で ID トークンを生成し、登録ホストのトップページの head に challenge の meta タグを置く。
3. サーバーは challenge を検証開始時に消費する。組織・ホスト・依頼者・現在の登録主体が一致し、署名検証済み ID トークンの発行者・audience・主体・時刻が一致することを確認する。
4. 登録ホストの HTTPS 443 に証明を取りに行く。TLS 証明書検証と公開 IP へのピン留めを行い、リダイレクトは追わない。head 内の token 完全一致だけを採用する。
5. いずれかが失敗すれば証明は成立せず、challenge は再利用できない。プロセス再起動でも未完了 challenge は失われる。

## 統合前に必要な作業

- 組織の権限付き設定として (組織, ホスト) → サービスアカウント sub を監査付きで保存する。登録・変更時は既存の診断権限を減らし、別組織から参照できないようにする。
- Google 公開鍵を使う署名検証器を実装し、issuer・audience・有効期限を検証する。鍵取得やキャッシュの障害時は fail-closed とする。
- aegis/server.py の組織ルートから TenantRegistry の該当 AssessmentService だけに接続する。既存の _get_org / _dispatch / _bind を通し、tests/test_tenancy.py に他組織の拒否を追加する。
- 所有証明を AssessmentService の署名付き proof と監査ログへ接続する。診断範囲の確認と L2 の別人承認は既存どおり別の段階とする。
- Cloud Run 実環境でのトークン形式と audience の互換性は未確認。実サービスへの通信やデプロイはこの PR では行わない。
