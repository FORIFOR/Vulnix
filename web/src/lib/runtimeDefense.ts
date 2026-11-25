export const runtimeChecks = [
  ["authentication", "認証", "未ログインの操作が拒否され、許可された利用者の操作が成功する。", "ログイン要件とセッションの期限を確認する。"],
  ["authorization", "認可", "権限のないテスト利用者の操作を拒否し、許可された役割だけが実行できる。", "管理画面の有効な役割と割当を確認する。"],
  ["isolation", "データ分離", "別の利用者や組織に属する合成データの読み取りと変更を拒否する。", "データベースやストレージで有効な組織分離の方針を確認する。"],
  ["webhook", "Webhook署名", "信頼した送信元の合成通知だけを受理し、署名なし・不正署名・期限外を拒否する。", "有効な受信経路で署名の検証が必須か確認する。"],
  ["input", "入力処理", "保護対象の入力を処理しても、副作用や意図しない書き込みが発生しない。", "使用中の入力検証と安全な出力方式を確認する。"],
  ["saml", "SAML", "テスト用IdPの正規署名を受理し、信頼しない署名を拒否する。", "使っているSSO方式と信頼対象、署名必須の設定を確認する。"],
  ["xml", "XML", "対象のXML処理で、許可されていない外部資源の読込が発生しない。", "実際に使用するXMLパーサーと、外部実体・DTD・読込先の設定を確認する。"],
  ["mfa", "MFA", "MFA対象のテストアカウントは、第二要素なしではログインできない。", "IdPまたは管理画面で、MFAの適用対象と例外を確認する。"],
  ["iam", "クラウドIAM", "合成資源に対して、稼働ロールに必要な操作だけが許可される。", "稼働主体に付いた実効権限と、継承・例外を読み取り専用で確認する。"],
  ["egress", "外向き通信", "許可宛先には接続でき、許可外の模擬宛先へ通信が出ない。", "配備先の有効な出口制限と、プロキシ経由の例外を確認する。"],
  ["container", "コンテナ権限", "稼働プロセスのUIDと権限が方針に一致し、不要な権限で操作できない。", "稼働中のUID、付与された権限、書込マウントを確認する。"],
  ["agent", "AIエージェント", "許可リスト外のツールと承認前の状態変更を拒否する。", "実行中のツール許可リスト、承認方針、上位設定の上書きを確認する。"],
  ["integrity", "成果物・永続化", "稼働主体がリリース成果物や保護された永続領域を変更できない。", "配備された成果物の署名と、永続領域の書込権限を確認する。"],
  ["infrastructure", "メール・VPN・ディレクトリ", "利用している経路で未認証・権限外の操作を拒否する。", "利用製品、認証方針、委任、失効の適用範囲を確認する。"],
] as const;

export type RuntimeCheck = (typeof runtimeChecks)[number];
export const evidenceLabels = {
  settings: "設定確認済み", runtime: "利用者確認（テスト結果）", action: "対策が必要", na: "根拠付き対象外",
} as const;
export type EvidenceKind = keyof typeof evidenceLabels;
export type EvidenceIdentity = { commit: string; deployment: string; digest: string };
export type Verdict = { kind: EvidenceKind; scope: string; detail: string; identity?: EvidenceIdentity };
export type JUnitReport = { tests: boolean[]; digest: string; commit: string; deployment: string; scope: string };
export const validCommit = (value: string) => /^(?:[0-9a-f]{40}|[0-9a-f]{64})$/i.test(value);
export const validDeployment = (value: string) => /^[a-z0-9][a-z0-9_.:@-]{0,127}$/i.test(value);

export const scopes = ["ローカルの対象環境", "隔離した模擬環境", "許可済みSTG"];
const maxReportBytes = 2 * 1024 * 1024;

export async function readJUnitReport(file: File): Promise<JUnitReport> {
  if (file.size > maxReportBytes || !file.size) throw new Error("report size");
  const bytes = await file.arrayBuffer();
  const text = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
  // DOMParser parses XML as data. Reject declarations capable of supplying resources or entities.
  if (/<!\s*(?:doctype|entity)\b|<\?(?!xml\s)/i.test(text)) throw new Error("unsupported XML declaration");
  const doc = new DOMParser().parseFromString(text, "application/xml");
  const root = doc.documentElement;
  if (doc.querySelector("parsererror") || doc.doctype || root.namespaceURI !== null ||
      !["testsuite", "testsuites"].includes(root.localName)) throw new Error("not a JUnit report");
  const cases = Array.from(root.getElementsByTagName("testcase"));
  if (!cases.length || cases.length > 5000) throw new Error("test count");
  const declared = root.getAttribute("tests");
  if (declared !== null && (!/^\d+$/.test(declared) || Number(declared) !== cases.length)) throw new Error("test count mismatch");
  const tests = cases.map((test) => {
    if (test.namespaceURI !== null || test.parentElement?.localName !== "testsuite" || !test.getAttribute("name") ||
        (test.hasAttribute("status") && !["run", "passed", "success"].includes(test.getAttribute("status") ?? ""))) return false;
    return Array.from(test.children).every(({ localName, namespaceURI }) => namespaceURI === null &&
      ["system-out", "system-err", "properties"].includes(localName));
  });
  const metadata = new Map<string, string>();
  const keys = new Set(["vulnix.commit", "vulnix.deployment", "vulnix.environment"]);
  for (const properties of Array.from(root.getElementsByTagName("properties")).filter((child) =>
    child.parentElement?.namespaceURI === null && ["testsuite", "testsuites"].includes(child.parentElement.localName))) {
    for (const property of Array.from(properties.children)) {
      const name = property.getAttribute("name");
      if (property.localName !== "property" || !name || !keys.has(name)) continue;
      const value = property.getAttribute("value") ?? "";
      if ((name === "vulnix.commit" && !validCommit(value)) ||
          (name === "vulnix.deployment" && !validDeployment(value)) ||
          (name === "vulnix.environment" && !scopes.includes(value))) throw new Error("invalid report metadata");
      const normalized = name === "vulnix.commit" ? value.toLowerCase() : value;
      if (metadata.has(name) && metadata.get(name) !== normalized) throw new Error("ambiguous report metadata");
      metadata.set(name, normalized);
    }
  }
  const digest = Array.from(new Uint8Array(await crypto.subtle.digest("SHA-256", bytes)),
    (byte) => byte.toString(16).padStart(2, "0")).join("");
  return { tests, digest, commit: metadata.get("vulnix.commit") ?? "", deployment: metadata.get("vulnix.deployment") ?? "",
    scope: metadata.get("vulnix.environment") ?? "" };
}
