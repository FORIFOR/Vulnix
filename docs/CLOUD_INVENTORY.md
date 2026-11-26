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
