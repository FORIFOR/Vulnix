# Google Cloud から診断対象を選ぶ

「サイト」画面で Google Cloud に接続し、表示されたプロジェクトを選びます。Google で同意するのはプロジェクト一覧の閲覧です。接続結果は操作した Vulnix セッションと組織にひも付き、一覧を取得するサーバー上の状態は10分で消えます。Google のアクセストークンはプロジェクト一覧の取得にだけ使い、ブラウザや保存先には渡しません。「Vulnixの連携を解除」で進行中の照会と一覧の公開を無効にします。Google側の同意を取り消す場合は、Googleアカウントの「サードパーティとの接続」でこのクライアントのアクセスを削除します。

Cloud Run コンソールの対象サービスから YAML 表示をコピーするか、保存したサービス定義を選びます。ブラウザでサービス名、既定URL、リビジョン名と定義上のイメージを抽出します。エクスポートの原文や設定値は Vulnix サーバーへ送りません。Cloud Run API のサービス一覧には `cloud-platform` スコープが必要なため、この読み取り専用の連携ではコンソールから取り込みます。コンソールで閲覧できない場合は、管理者に対象サービスの Cloud Run Viewer 権限を確認してください。 [Cloud Run API](https://docs.cloud.google.com/run/docs/reference/rest/v2/projects.locations.services/list) · [Cloud Run IAM](https://docs.cloud.google.com/run/docs/reference/iam/roles)

選択したサービスのURLから、既存の所有確認と診断範囲の設定に進みます。Google Cloud の閲覧や定義の取り込みから、所有確認済みまたは診断許可済みとは判定しません。独自ドメインや他のホスティング先は「＋ サイトを診断する」からURLを入力し、DNSまたは確認用ファイルを選べます。必要な承認がそろった対象の診断・再検証は既存画面から進めます。

依存関係を調べる場合は「フォルダ・SBOMを診断する」からローカルフォルダ、または既存の CycloneDX または SPDX 2.3 の JSON を選びます。SBOM の照合対象は読み取れる CPE と npm・PyPI・Go の固定版の PURL です。対象イメージのSBOMを使用してください。Artifact Registry のイメージダイジェストの「依存関係」から既存SBOMの保存先を確認できます。必要な場合は対象リポジトリを読む権限、分析記録を読む権限、ファイルを読む権限（`storage.objects.get`）だけを管理者に依頼してください。実配備との一致や実行時の影響は別途確認が必要です。

## 運用者による初期設定

この連携専用の OAuth ウェブクライアントを用意し、Cloud Resource Manager API を有効にします。使用する Vulnix のHTTPSオリジンの `/verify/cloud` を転送先に登録し、`VULNIX_CLOUD_CLIENT_ID`、`VULNIX_CLOUD_CLIENT_SECRET`、`VULNIX_CLOUD_REDIRECT_URI` をバックエンドに設定します。OAuth同意画面の対象ユーザーと公開要件は運用者が管理します。プロジェクトの表示対象は OAuth で選んだ Google アカウントに `resourcemanager.projects.get` がある範囲です。 [Cloud Resource Manager API](https://docs.cloud.google.com/resource-manager/reference/rest/v3/projects/search) · [OAuth クライアントの設定](https://developers.google.com/identity/protocols/oauth2/web-server)

接続の状態は単一のバックエンドプロセスに保持します。複数レプリカでは、開始、Googleからの戻り、一覧取得を同じプロセスに送る構成が必要です。プロセスが切り替わると再接続が必要です。

## Cloud Runの自動参照方式を評価

- Cloud Resource Manager は `cloud-platform.read-only` でプロジェクト一覧を取得できます。Cloud Run v2 のサービス一覧、サービス取得、リビジョン取得には `cloud-platform` が必要です。IAM の Cloud Run Viewer を付与しても、既存のユーザー権限までそのロールに限定される仕組みではありません。 [プロジェクト一覧](https://docs.cloud.google.com/resource-manager/reference/rest/v3/projects/search) · [Cloud Run サービス一覧](https://docs.cloud.google.com/run/docs/reference/rest/v2/projects.locations.services/list)
- Google の Credential Access Boundary によるダウンスコープは Cloud Storage 向けで、Cloud Run には適用できません。 [Credential Access Boundary](https://docs.cloud.google.com/iam/docs/downscoping-short-lived-credentials)
- 管理者が専用のワークロードIDに `run.services.list`、`run.services.get`、`run.revisions.get` だけを与える方法もあります。採用には、利用者ごとの権限を検証し、別組織への代理参照を防ぐ設定とその運用が必要です。現在は広いスコープや代理権限を追加せず、コンソールの定義取り込みを使います。 [Cloud Run IAM](https://docs.cloud.google.com/run/docs/reference/iam/roles)

## 所有確認の通信申請

受入環境では `VULNIX_OWNERSHIP_TRAFFIC=approved` を指定する。診断通信を停止したまま実施する場合は、別途 `VULNIX_REAL_SERVICE_DIAGNOSIS=0` を指定する。両方を停止する場合は `VULNIX_OWNERSHIP_TRAFFIC=off` と `VULNIX_REAL_SERVICE_DIAGNOSIS=0` を使う。所有確認用の通信設定を省略した旧環境は、既存の診断通信設定に従う。

1. 担当者が「診断対象の管理」で対象を開き、確認方法を選んで通信許可を申請する。
2. 別の組織管理者が、同じ対象と方法を開く。所有者の許可範囲と日時を確認し、承認または拒否する。
3. 依頼者が有効期限内に所有確認を実行する。承認は15分間有効。緊急停止、再登録による宛先変更、プロセス再起動で承認は使えなくなる。
4. 所有確認後、診断範囲と実行許可の既存手続きに進む。

### Google Search Console の運営者設定

運営者が Google Auth Platform で HTTPS を使うウェブクライアントを用意する。戻り先は Vulnix の公開オリジンまたは信頼済みの受入オリジンの `/verify/google`。サーバーの保護された設定に `VULNIX_GOOGLE_CLIENT_ID`、`VULNIX_GOOGLE_CLIENT_SECRET`、`VULNIX_GOOGLE_REDIRECT_URI` を設定し、読み取り専用の Search Console スコープを用意する。利用者は画面で自分の Google アカウントを選ぶ。Google Cloud のプロジェクト閲覧は独立した連携で、戻り先は `/verify/cloud`。

ローカル受入はこのMacの管理下にある信頼済み証明書を使う。証明書警告が出る場合は、運営者が受入オリジンと証明書の設定を確認してから利用者に渡す。
