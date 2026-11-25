type Category = "ARTEX" | "CVE" | "Claude Code";
type Status = "confirmed" | "action" | "unknown" | "na";
type Result = { location?: { path: string; line?: number }; category: Category; title: string; status: Status; evidence: string; risk: string; fix: string; retest: string };
type RecordValue = Record<string, unknown>;

export const categories = ["ARTEX", "CVE", "Claude Code"] as const;
export const labels: Record<Status, string> = {
  confirmed: "防御確認済み", action: "対策が必要", unknown: "未確認", na: "対象外",
};

export const controls = [
  ["saml", "ARTEX", "SAML署名の強制", "認証のなりすまし", "信頼するIdPの署名を必須にする", "署名なしの入力を拒否する既存の認証テストを確認する"],
  ["xml", "ARTEX", "XML外部実体の無効化", "内部サービスやファイルの露出", "XMLパーサーの外部実体・DTDを無効にする", "使用中のパーサーと実効設定を確認する"],
  ["cloud", "ARTEX", "クラウド権限とメタデータの制限", "アプリからの権限拡大", "メタデータへのアクセスを制限し、サービスロールの管理権限を削る", "実効ネットワーク設定とIAMポリシーを確認する"],
  ["surface", "ARTEX", "管理面・ディレクトリ公開の制限", "管理面や内部資料の露出", "公開ディレクトリと管理面を閉じ、運用経路を分離する", "公開ルートとデプロイ設定を照合する"],
  ["access", "Claude Code", "資源単位のアクセス制御", "別アカウントのデータへのアクセス", "すべてのデータ取得にサーバー側の所有者・組織判定を入れる", "権限外の要求を拒否する既存の認可テストを確認する"],
  ["accounts", "Claude Code", "認証強化と試行制限", "漏えいした資格情報による不正アクセス", "管理者にMFAを必須にし、認証試行を制限する", "認証設定と試行制限のテストを確認する"],
  ["secrets", "Claude Code", "資格情報の分離と失効", "資格情報の再利用による被害拡大", "本番鍵を分離して最小権限にし、漏えい時に失効できる手順を整える", "秘密値を含まない棚卸しと失効記録を確認する"],
  ["egress", "Claude Code", "外向き通信とデータアクセスの制限", "データ持ち出しと内部への横展開", "実行主体の権限を絞り、外向き通信を必要な宛先だけに絞る", "隔離環境の拒否記録と実効ポリシーを照合する"],
] as const;

export function record(value: unknown): RecordValue {
  return value !== null && typeof value === "object" && !Array.isArray(value) ? value as RecordValue : {};
}

function evidenceText(value: unknown): string {
  return typeof value === "string" ? value.trim().slice(0, 1000) : "";
}

export function checkControls(input: unknown): Result[] {
  return controls.map(([key, category, title, risk, fix, retest]) => {
    const item = record(record(input)[key]);
    const evidence = evidenceText(item.evidence);
    let status: Status = "unknown";
    if (evidence) {
      if (item.applicable === false && item.enabled === undefined) status = "na";
      else if (item.applicable !== false && item.enabled === true) status = "confirmed";
      else if (item.applicable !== false && item.enabled === false) status = "action";
    }
    return { category, title, status, risk, fix, retest, evidence: evidence || "設定やテスト結果の根拠が未入力です。" };
  });
}

function versionParts(value: unknown): number[] | null {
  return typeof value === "string" && /^\d{1,9}(\.\d{1,9}){1,7}$/.test(value)
    ? value.split(".").map(Number) : null;
}

function compare(a: number[], b: number[]): number {
  for (let i = 0; i < Math.max(a.length, b.length); i++) {
    const diff = (a[i] ?? 0) - (b[i] ?? 0);
    if (diff) return diff;
  }
  return 0;
}

function matchesCpe(rule: RecordValue, component: RecordValue): boolean {
  if (rule.vulnerable !== true || typeof rule.criteria !== "string") return false;
  const [format, schema, type, vendor, product, exact] = rule.criteria.split(":");
  if (format !== "cpe" || schema !== "2.3" || type !== "a" || vendor !== component.vendor || product !== component.product) return false;
  const version = versionParts(component.version);
  if (!version) return false;
  if (exact !== "*") {
    const target = versionParts(exact);
    if (!target || compare(version, target) !== 0) return false;
  }
  const bounds = [
    ["versionStartIncluding", (d: number) => d >= 0], ["versionStartExcluding", (d: number) => d > 0],
    ["versionEndIncluding", (d: number) => d <= 0], ["versionEndExcluding", (d: number) => d < 0],
  ] as const;
  return bounds.every(([key, accepts]) => {
    if (!(key in rule)) return true;
    const bound = versionParts(rule[key]);
    return bound !== null && accepts(compare(version, bound));
  });
}

function list(value: unknown): RecordValue[] {
  return Array.isArray(value) ? value.map(record) : [];
}

export function checkCves(components: unknown, feed: unknown): Result[] {
  const entries = list(record(feed).vulnerabilities);
  const result: Result[] = [];
  const inventory = list(components);
  for (const [index, component] of inventory.slice(0, 200).entries()) {
    const start = result.length;
    for (const entry of entries) {
      const cve = record(entry.cve);
      if (typeof cve.id !== "string" || !/^CVE-\d{4}-\d{4,}$/.test(cve.id)) continue;
      const match = list(cve.configurations).some((config) => list(config.nodes).some(
        (node) => list(node.cpeMatch).some((rule) => matchesCpe(rule, component)),
      ));
      if (!match) continue;
      const review = record(record(component.reviews)[cve.id]);
      const evidence = evidenceText(review.evidence);
      let status: Status = "unknown";
      if (evidence && review.applies === false && review.patched === undefined) status = "na";
      if (evidence && review.applies === true && review.patched === true) status = "confirmed";
      if (review.applies === true && review.patched === false) status = "action";
      result.push({
        category: "CVE", title: String(component.product) + " " + String(component.version) + " · " + cve.id, status,
        evidence: evidence || "入力した製品・バージョンがカタログに一致しました。影響条件と修正状況はベンダー勧告で確認してください。",
        risk: "影響条件を満たす構成では、勧告に記載された影響を受けます。",
        fix: "ベンダー勧告の修正版を適用し、必要な構成変更を行う。",
        retest: "導入済みビルド、影響条件、修正の記録を更新して再検証する。",
      });
    }
    if (result.length === start) {
      result.push(cveNotChecked(`製品 ${index + 1} の公開CVEとの照合`,
        "候補を照合できませんでした。入力、フィード範囲、CPEとバージョンの形式を確認してください。"));
    }
  }
  if (inventory.length > 200) {
    result.push(cveNotChecked("残りの製品", "1回に照合できる製品は200件です。残りは別に入力してください。"));
  }
  return result.length ? result : [cveNotChecked("公開CVEとの照合", "製品・バージョンの情報が未入力です。")];
}

function cveNotChecked(title: string, evidence: string): Result {
  return {
    category: "CVE", title, status: "unknown", evidence,
    risk: "未登録の製品、未収録のCVE、比較できない版が残る可能性があります。",
    fix: "製品のベンダー名・製品名・導入版を確認し、最新のNVD JSONを読み込む。",
    retest: "情報を更新して再検証する。",
  };
}

export const demoEvidence = {
  controls: {
    saml: { enabled: true, evidence: "模擬の認証テストで未署名の入力を拒否" },
    xml: { enabled: false, evidence: "模擬設定では外部実体の無効化が未設定" },
    access: { enabled: true, evidence: "模擬の認可テストで別組織へのアクセスを拒否" },
    accounts: { enabled: false, evidence: "模擬設定では管理者MFAが任意" },
  },
  components: [{ vendor: "apache", product: "http_server", version: "2.4.49", reviews: {
    "CVE-2021-41773": { applies: true, patched: false, evidence: "模擬インベントリの対象構成。修正記録なし" },
  } }],
};

export function checkSource(source: string): Result {
  const candidates = source.split(/\r?\n/).flatMap((line, index) =>
    /\bdangerouslySetInnerHTML\b|\.innerHTML\s*=/.test(line) ? [index + 1] : []).slice(0, 20);
  return {
    category: "Claude Code", title: "JavaScript / JSX のHTML書き込み候補", status: "unknown",
    evidence: candidates.length
      ? `確認候補は ${candidates.join("、")}行目。コメントや安全な固定値も候補に含まれます。`
      : "対象の書き込みパターンは見つかりませんでした。間接呼び出しや別ファイルのデータ経路は未確認です。",
    risk: "外部入力がそのままHTMLとして描画される場合、閲覧者の権限で処理が実行されるおそれがあります。",
    fix: "文字列はテキストとして描画する。HTMLが必要ならレビュー済みのサニタイザーを使う。",
    retest: "入力から描画までを確認し、変更したファイルを再検証する。",
  };
}

export function checkLockfile(input: unknown): Result {
  const lock = record(input);
  const packages = [2, 3].includes(Number(lock.lockfileVersion)) ? record(lock.packages) : {};
  const entries = Object.entries(packages).filter(([path]) => path !== "");
  const cleartext = entries.filter(([, value]) => {
    const resolved = record(value).resolved;
    return typeof resolved === "string" && /^http:\/\//i.test(resolved);
  });
  return {
    category: "ARTEX", title: "npm依存関係の取得元", status: cleartext.length ? "action" : "unknown",
    evidence: cleartext.length ? `HTTPの取得元が ${cleartext.length} 件あります。`
      : entries.length ? `${entries.length} 件を照合。HTTPの取得元は見つかりませんでした。実際の取得先と完全性は未確認です。`
        : "npm lockfile v2/v3の依存関係を確認できませんでした。",
    risk: "取得経路が暗号化されていない場合、サーバー認証と経路上の改変の防止ができません。",
    fix: "信頼するHTTPSレジストリを指定し、ロックファイルを更新する。依存関係の整合性も確認する。",
    retest: "更新した package-lock.json を再度選んで照合する。",
  };
}

export function checkCloudFormation(input: unknown): Result[] {
  const resources = record(record(input).Resources);
  return Object.entries(resources).flatMap(([id, resource]) => {
    const item = record(resource);
    if (item.Type !== "AWS::EC2::LaunchTemplate") return [];
    const metadata = record(record(record(item.Properties).LaunchTemplateData).MetadataOptions);
    let status: Status = "unknown";
    let evidence = "メタデータの保護設定をテンプレートから確定できません。";
    if (metadata.HttpEndpoint === "disabled") {
      status = "confirmed";
      evidence = "テンプレートでメタデータのHTTPエンドポイントを無効化。";
    } else if (metadata.HttpTokens === "required") {
      status = "confirmed";
      evidence = "テンプレートでIMDSv2トークンが必須。";
    } else if (metadata.HttpEndpoint === "enabled" && metadata.HttpTokens === "optional") {
      status = "action";
      evidence = "テンプレートでHTTPエンドポイントが有効で、IMDSv2トークンが任意。";
    } else if (metadata.HttpTokens === "optional") {
      evidence = "トークンは任意ですが、HTTPエンドポイントの有効状態は未確認です。";
    }
    return [{
      category: "ARTEX", status, title: `EC2メタデータ設定 ／ ${id.slice(0, 100)}`, evidence,
      risk: "旧方式のメタデータアクセスを許すと、意図しないサービス資格情報の取得につながる場合があります。",
      fix: "メタデータを無効にするか、IMDSv2トークンを必須にする。サービスロールの権限も制限する。",
      retest: "設定修正後にテンプレートを再入力し、別途デプロイ済みインスタンスの実効設定を確認する。",
    }];
  });
}
