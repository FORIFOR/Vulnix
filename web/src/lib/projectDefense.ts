import ts from "typescript";
import { affects, collectPackages, propertyLine, type Package, type Location } from "./projectPackages";
import { checkCloudFormation, checkControls, checkLockfile, record } from "./quickDefense";

export const limits = { entries: 12000, files: 180, fileBytes: 256 * 1024, dependencyBytes: 4 * 1024 * 1024, bytes: 12 * 1024 * 1024 };
export type ProjectFile = { file: File; path: string };
type Result = ReturnType<typeof checkControls>[number];
type Component = { location?: Location; part: string; vendor: string; product: string; version: string };
const excluded = /^(?:\.|node_modules$|vendor$|dist$|build$|coverage$|target$|__pycache__$|secrets?$)/i;
const source = /\.(?:[cm]?[jt]s|[jt]sx|py|rb|php|go|rs|java|cs)$/i;
const artifact = /^(?:gitleaks-redacted\.json|package(?:-lock)?\.json|npm-shrinkwrap\.json|requirements[^/]*\.txt|pyproject\.toml|poetry\.lock|uv\.lock|yarn\.lock|pnpm-lock\.yaml|go\.(?:mod|sum)|Cargo\.(?:toml|lock)|Gemfile(?:\.lock)?|composer\.(?:json|lock)|pom\.xml|Dockerfile(?:\.[\w-]+)?|.*(?:sbom|cloudformation|template|cfn|manifest|k8s|policy).*\.json)$/i;

export function classifyPath(path: string) {
  const parts = path.split("/");
  const name = parts.pop() ?? "";
  if (parts.slice(1).some((part) => excluded.test(part)) ||
      excluded.test(name) || /(?:secret|credential|private.?key)|(?:\.min\.|\.generated\.)/i.test(name)) return null;
  if (artifact.test(name)) return { name, priority: 0 };
  if (source.test(name)) return { name, priority: /auth|access|db|sql|xml|render|route|handler/i.test(name) ? 1 : 2 };
  return null;
}

function item(category: Result["category"], title: string, status: Result["status"], evidence: string, fix: string): Result {
  return {
    category, title, status, evidence, fix,
    risk: category === "CVE" ? "影響を受ける版や設定のまま運用すると、公開済みの問題が残る可能性があります。" :
      "入力処理や実効設定によっては、認可されていない操作や情報公開につながります。",
    retest: "変更を保存し、プロジェクトフォルダを選び直して検証してください。",
  };
}

function jsFlow(name: string, input: string, path: string): Result[] {
  const tree = ts.createSourceFile(name, input, ts.ScriptTarget.Latest, true);
  const results: Result[] = [];
  const imports = new Map<string, string>();
  for (const declaration of tree.statements) {
    if (!ts.isImportDeclaration(declaration) || !ts.isStringLiteral(declaration.moduleSpecifier)) continue;
    const members = declaration.importClause?.namedBindings;
    if (!members || !ts.isNamedImports(members)) continue;
    for (const member of members.elements) {
      if (member.isTypeOnly || declaration.importClause?.isTypeOnly) continue;
      const id = `${declaration.moduleSpecifier.text}:${(member.propertyName ?? member.name).text}`;
      imports.set(member.name.text, id);
    }
  }
  function literalOptions(node: ts.Expression | undefined) {
    if (!node || !ts.isObjectLiteralExpression(node) || node.properties.some((prop) =>
      !ts.isPropertyAssignment(prop) || !(ts.isIdentifier(prop.name) || ts.isStringLiteral(prop.name)))) return null;
    const options = new Map<string, boolean | null>();
    for (const prop of node.properties) {
      if (!ts.isPropertyAssignment(prop) || !(ts.isIdentifier(prop.name) || ts.isStringLiteral(prop.name))) continue;
      options.set(prop.name.text, prop.initializer.kind === ts.SyntaxKind.TrueKeyword ? true :
        prop.initializer.kind === ts.SyntaxKind.FalseKeyword ? false : null);
    }
    return options;
  }
  function configCall(expr: ts.Expression) {
    if (!(ts.isNewExpression(expr) || ts.isCallExpression(expr)) || !ts.isIdentifier(expr.expression)) return;
    const binding = imports.get(expr.expression.text);
    const saml = ts.isNewExpression(expr) && (binding === "@node-saml/node-saml:SAML" || binding === "@node-saml/passport-saml:Strategy");
    const xml = ts.isCallExpression(expr) && (binding === "libxmljs:parseXml" || binding === "libxmljs:parseXmlString");
    if (!saml && !xml) return;
    const options = literalOptions(expr.arguments?.[saml ? 0 : 1]);
    const clear = saml && options?.get("wantAssertionsSigned") === true && options.get("wantAuthnResponseSigned") === true;
    const risk = xml && ["noent", "dtdload", "replaceEntities", "dtdvalid"].some((key) => options?.get(key) === true);
    results.push({ ...item("ARTEX", saml ? "SAML署名要件の明示設定" : "XML外部実体・DTD設定",
      risk ? "action" : clear ? "confirmed" : "unknown",
      clear ? "指定したライブラリ呼び出しで防御設定を明示しています。実際に使われる設定は未確認です。" :
        risk ? "対象の呼び出しで実体の展開または外部DTDの読込を有効にしています。" :
          "この呼び出しでは設定が省略または動的です。実効設定を確認してください。",
      saml ? "信頼するIdP、メッセージの署名必須条件、導入済みのライブラリ版、拒否テストを確認する。" :
        "外部実体・DTDを無効にし、外部資源の読込を禁止してパーサー設定を確認する。"),
      location: { path, line: line(expr) } });
  }
  const sourceNames = new Set(["query", "body", "params"]);
  const line = (node: ts.Node) => tree.getLineAndCharacterOfPosition(node.getStart(tree)).line + 1;
  function trace(node: ts.Expression, bindings: Map<string, boolean>): boolean {
    if (ts.isParenthesizedExpression(node)) return trace(node.expression, bindings);
    if (ts.isIdentifier(node)) return bindings.get(node.text) === true;
    if (ts.isPropertyAccessExpression(node)) {
      return (ts.isIdentifier(node.expression) && /^(req|request)$/.test(node.expression.text) &&
        sourceNames.has(node.name.text)) || trace(node.expression, bindings);
    }
    if (ts.isTemplateExpression(node)) return node.templateSpans.some((span) => trace(span.expression, bindings));
    return ts.isBinaryExpression(node) && node.operatorToken.kind === ts.SyntaxKind.PlusToken &&
      (trace(node.left, bindings) || trace(node.right, bindings));
  }
  function block(statements: ts.NodeArray<ts.Statement>) {
    const bindings = new Map<string, boolean>();
    // Keep only immutable aliases declared earlier at this statement level.
    for (const statement of statements) {
      if (results.length >= 10) return;
      if (ts.isVariableStatement(statement) && (statement.declarationList.flags & ts.NodeFlags.Const)) {
        for (const decl of statement.declarationList.declarations) {
          if (ts.isIdentifier(decl.name) && decl.initializer) {
            bindings.set(decl.name.text, trace(decl.initializer, bindings));
            if (statements === tree.statements) configCall(decl.initializer);
          }
        }
      }
      if (ts.isExpressionStatement(statement)) {
        const expr = statement.expression;
        if (ts.isBinaryExpression(expr) && ts.isPropertyAccessExpression(expr.left) &&
          ["innerHTML", "textContent"].includes(expr.left.name.text) && expr.operatorToken.kind === ts.SyntaxKind.EqualsToken) {
          const fromRequest = trace(expr.right, bindings);
          const asText = expr.left.name.text === "textContent";
          if (asText && !fromRequest) continue;
          results.push({ ...item("Claude Code", "外部入力とHTML出力", fromRequest ? (asText ? "confirmed" : "action") : "unknown",
            `ソースの${line(expr)}行目。 ${asText ? "要求データをテキストとして書き込む経路です。" :
              fromRequest ? "要求データからHTML書き込みへの直接経路を確認しました。" : "HTML書き込みの入力元を確定できません。"}`,
            "文字列はテキストとして描画し、HTMLが必要な場合はサニタイザーを通す。"), location: { path, line: line(expr) } });
        }
      }
      ts.forEachChild(statement, visit);
    }
  }
  function visit(node: ts.Node) {
    if (results.length >= 10) return;
    if (ts.isBlock(node)) block(node.statements);
    else ts.forEachChild(node, visit);
  }
  block(tree.statements);
  return results;
}

function cloudStorage(input: unknown, path: string, body: string): Result[] {
  return Object.entries(record(record(input).Resources)).flatMap(([id, resource]) => {
    const bucket = record(resource);
    if (bucket.Type !== "AWS::S3::Bucket") return [];
    const policy = record(record(bucket.Properties).PublicAccessBlockConfiguration);
    const complete = ["BlockPublicAcls", "IgnorePublicAcls", "BlockPublicPolicy", "RestrictPublicBuckets"]
      .every((field) => policy[field] === true);
    return [{ ...item("Claude Code", "ストレージの公開防止", complete ? "confirmed" : "unknown",
      complete ? "S3バケットのテンプレートに公開を防ぐ4設定が明示されています。" :
        "テンプレートだけでは公開を防ぐ設定を確認できません。アカウント側の設定や稼働状態も確認してください。",
      "公開不要のバケットでは公開アクセスのブロックを有効にし、組織・アカウント・バケット設定を照合する。"), location: { path, line: propertyLine(body, id) } }];
  });
}

function deploymentChecks(name: string, body: string, input: unknown, path: string): Result[] {
  const spec = record(input);
  const settings = record(spec.spec);
  const results: Result[] = [];
  const add = (title: string, status: Result["status"], evidence: string, fix: string, line?: number) =>
    results.push({ ...item("ARTEX", title, status, evidence, fix), location: { path, line } });
  if (spec.apiVersion === "networking.k8s.io/v1" && spec.kind === "NetworkPolicy" &&
      Array.isArray(settings.policyTypes) && settings.policyTypes.includes("Egress")) {
    const egress = settings.egress;
    const all = Array.isArray(egress) && egress.some((rule) =>
      rule !== null && typeof rule === "object" && !Array.isArray(rule) && Object.keys(rule).length === 0);
    add("Kubernetesの外向き通信", all ? "action" : "unknown", all ?
      "このポリシーに宛先・ポートを制限しない送信規則があります。" :
      "他のポリシーとの合成とネットワーク機能の実効性が未確認です。",
      "ポッドを選ぶ全ポリシーと例外を照合し、必要な宛先・ポートに限定する。", propertyLine(body, "egress"));
  }
  if (spec.apiVersion === "rbac.authorization.k8s.io/v1" && ["Role", "ClusterRole"].includes(String(spec.kind))) {
    const wildcard = array(spec.rules).some((rule) => ["verbs", "resources", "apiGroups"].some((key) =>
      Array.isArray(rule[key]) && rule[key].includes("*")));
    add("Kubernetesの権限範囲", wildcard ? "action" : "unknown", wildcard ?
      "明示した権限にワイルドカードがあり、操作やリソースの範囲が広がります。" :
      "ロールの付与先と、他のロールを含む実効権限が未確認です。",
      "必要な操作とリソースに限定し、付与先と継承権限を確認する。", propertyLine(body, "rules"));
  }
  for (const [id, entry] of Object.entries(record(spec.Resources))) {
    const resource = record(entry);
    const properties = record(resource.Properties);
    if (resource.Type === "AWS::EC2::SecurityGroup") {
      const publicAdmin = array(properties.SecurityGroupIngress).some((rule) => {
        if (rule.CidrIp !== "0.0.0.0/0" && rule.CidrIpv6 !== "::/0") return false;
        if (rule.IpProtocol === "-1") return true;
        return (rule.IpProtocol === "tcp" || rule.IpProtocol === "6") &&
          typeof rule.FromPort === "number" && typeof rule.ToPort === "number" &&
          [22, 3389].some((port) => Number(rule.FromPort) <= port && port <= Number(rule.ToPort));
      });
      if (publicAdmin) add("管理ポートの公開範囲", "action",
        "テンプレートがSSHまたはリモートデスクトップを全インターネットから許可します。配備先は未確認です。",
        "管理用の送信元を許可リストに絞り、付与されたグループと実効ルートを確認する。", propertyLine(body, id));
    }
    if (resource.Type === "AWS::ApiGatewayV2::Stage") {
      const defaults = record(properties.DefaultRouteSettings);
      const capped = typeof defaults.ThrottlingRateLimit === "number" && defaults.ThrottlingRateLimit > 0 &&
        typeof defaults.ThrottlingBurstLimit === "number" && defaults.ThrottlingBurstLimit > 0;
      add("APIの試行回数制限", capped ? "confirmed" : "unknown",
        capped ? "このテンプレートにAPIステージの既定スロットリングを明示しています。経路別の上書きは未確認です。" :
          "既定の制限値をこのテンプレートから確認できません。",
        "経路別の上書きと利用者単位の制限、実際に使用中のステージを確認する。", propertyLine(body, id));
    }
    if (results.length >= 20) break;
  }
  if (/^Dockerfile(?:\.|$)/i.test(name)) {
    const lines = body.split(/\r?\n/);
    let user: { value: string; line: number } | undefined;
    for (const [i, line] of lines.entries()) {
      if (/^\s*FROM\s+/i.test(line)) user = undefined;
      const match = line.match(/^\s*USER\s+(\S+)\s*$/i);
      if (match) user = { value: match[1].split(":")[0], line: i + 1 };
    }
    const root = user && /^(root|0+)$/i.test(user.value);
    add("コンテナの既定ユーザー", root ? "action" : "unknown", root ?
      "最終ステージでrootユーザーを明示しています。" : "実行時のユーザーと書き込み権限が未確認です。",
      "必要な権限だけを持つ実行ユーザーを設定し、実行時の上書きと書き込み可能な領域を確認する。", user?.line);
  }
  if (source.test(name)) {
    const marker = body.split(/\r?\n/).findIndex((line) =>
      /-----BEGIN (?:OPENSSH |RSA |EC |DSA |ENCRYPTED )?PRIVATE KEY-----/.test(line));
    if (marker >= 0) {
      results.push({ ...item("Claude Code", "ソース内の秘密鍵形式", "unknown",
        "秘密鍵形式の開始マーカーがあります。テスト用・文書用の例か、実用の鍵かを確認してください。",
        "実用の鍵ならリポジトリから除き、失効・再発行して秘密管理サービスで保管する。"),
        location: { path, line: marker + 1 } });
    }
  }
  return results;
}

function componentsFrom(file: string, body: string, parsed: unknown, path: string): Component[] {
  if (/^Dockerfile(?:\.|$)/i.test(file)) {
    return [...body.matchAll(/^\s*FROM\s+(?:docker\.io\/library\/|library\/)?httpd:(\d+\.\d+\.\d+)\s*(?:$|#)/gim)]
      .map((match) => ({ part: "a", vendor: "apache", product: "http_server", version: match[1], location: { path, line: body.slice(0, match.index).split("\n").length } }));
  }
  const sbom = record(parsed);
  if (sbom.bomFormat !== "CycloneDX" || !Array.isArray(sbom.components)) return [];
  return sbom.components.slice(0, 200).flatMap((value: unknown) => {
    const match = typeof record(value).cpe === "string" &&
      String(record(value).cpe).match(/^cpe:2\.3:([aho]):([\w.-]+):([\w.-]+):(\d+(?:\.\d+){1,7})(?::\*){7}$/);
    return match ? [{ part: match[1], vendor: match[2], product: match[3], version: match[4], location: { path, line: propertyLine(body, "components") } }] : [];
  });
}

function numeric(left: string, right: unknown) {
  if (typeof right !== "string" || !/^\d{1,9}(?:\.\d{1,9}){1,7}$/.test(right) ||
      !/^\d{1,9}(?:\.\d{1,9}){1,7}$/.test(left)) return null;
  const a = left.split(".").map(Number);
  const b = right.split(".").map(Number);
  for (let i = 0; i < Math.max(a.length, b.length); i++) {
    const diff = (a[i] ?? 0) - (b[i] ?? 0);
    if (diff) return diff;
  }
  return 0;
}

function matches(rule: Record<string, unknown>, inventory: Component[]): boolean | null {
  const parsed = typeof rule.criteria === "string" &&
    rule.criteria.match(/^cpe:2\.3:([aho]):([\w.-]+):([\w.-]+):(\*|\d+(?:\.\d+){1,7})(?::\*){7}$/);
  if (!parsed || typeof rule.vulnerable !== "boolean") return null;
  const same = inventory.filter((c) => c.part === parsed[1] && c.vendor === parsed[2] && c.product === parsed[3]);
  const bounds = [
    ["versionStartIncluding", (n: number) => n >= 0], ["versionStartExcluding", (n: number) => n > 0],
    ["versionEndIncluding", (n: number) => n <= 0], ["versionEndExcluding", (n: number) => n < 0],
  ] as const;
  for (const c of same) {
    if (parsed[4] !== "*" && numeric(c.version, parsed[4]) !== 0) continue;
    if (bounds.every(([key, valid]) => {
      if (!(key in rule)) return true;
      const difference = numeric(c.version, rule[key]);
      return difference !== null && valid(difference);
    })) return true;
  }
  // A repository inventory cannot establish that a product or alternate build is absent.
  return null;
}

function array(input: unknown) {
  return Array.isArray(input) ? input.map(record) : [];
}

export function projectCves(feed: unknown, inventories: Component[][]): Result[] {
  const results: Result[] = [];
  for (const entry of array(record(feed).vulnerabilities)) {
    const cve = record(entry.cve);
    if (typeof cve.id !== "string" || !/^CVE-\d{4}-\d{4,}$/.test(cve.id) ||
      ["Rejected", "Disputed"].includes(String(cve.vulnStatus))) continue;
    let candidate = false;
    let applicable = false;
    let location: Location | undefined;
    for (const inventory of inventories) for (const config of array(cve.configurations)) {
      if (config.negate === true) continue;
      const nodes = array(config.nodes).map((node) => {
        const rules = array(node.cpeMatch);
        const identified = rules.map((rule) => matches(rule, inventory) === true);
        const positive = rules.some((rule, i) => rule.vulnerable === true && identified[i]);
        if (positive) {
          candidate = true;
          location ??= inventory.find((component) => rules.some((rule) =>
            rule.vulnerable === true && matches(rule, [component]) === true))?.location;
        }
        if (node.negate === true || !rules.length) return { met: false, positive: false };
        const met = node.operator === "AND" ? identified.every(Boolean) :
          node.operator === "OR" && identified.some(Boolean);
        return { met, positive: met && positive };
      });
      const hasVulnerable = nodes.some((node) => node.positive);
      const groupMet = nodes.length === 1 ? nodes[0].met :
        config.operator === "AND" ? nodes.every((node) => node.met) :
        config.operator === "OR" && nodes.some((node) => node.met);
      if (hasVulnerable && groupMet) applicable = true;
    }
    if (candidate) results.push({ ...item("CVE", cve.id, "unknown", applicable ?
      "プロジェクト資料にカタログ上の製品・版・構成条件の組み合わせがあります。実稼働構成と配布元の修正は未確認です。" :
      "製品・版は候補に一致します。必要な構成条件の一部を確認できません。",
      "配布元の勧告で導入済みビルド、修正の有無、影響条件を照合し、必要な更新を適用する。"), location });
    if (results.length >= 100) {
      results.push(item("CVE", "残りのCVE候補", "unknown", "候補表示の上限に達しました。", "対象を分割して検証する。"));
      break;
    }
  }
  return results.length ? results : [item("CVE", "公開CVEとの照合", "unknown",
    "同梱または選択したカタログで照合できる製品・構成の候補がありません。依存関係名だけでは製品を特定できません。",
    "稼働中の製品と版を確認し、必要に応じてCPE付きのCycloneDXと最新のNVDカタログを選ぶ。")];
}

function osvCves(feed: unknown, packages: Map<string, Package[]>) {
  const results: Result[] = [];
  for (const osv of array(feed)) {
    if (osv.withdrawn) continue;
    const id = (Array.isArray(osv.aliases) ? [...osv.aliases, osv.id] : [osv.id])
      .find((value) => typeof value === "string" && /^CVE-\d{4}-\d{4,}$/.test(value));
    if (!id) continue;
    for (const affected of array(osv.affected)) {
      const pkg = record(affected.package);
      if (!["npm", "PyPI", "Go"].includes(String(pkg.ecosystem)) || typeof pkg.name !== "string") continue;
      const name = pkg.ecosystem === "PyPI" ? pkg.name.toLowerCase().replace(/[-_.]+/g, "-") : pkg.name;
      const match = packages.get(`${pkg.ecosystem}:${name}`)?.find((entry) => affects(entry.version, entry.ecosystem, affected));
      if (match) {
        results.push({ ...item("CVE", id, "action",
          `${match.ecosystem}の依存関係資料にある版が、選択した勧告の影響条件に一致しました。実行環境の版と到達性は未確認です。`,
          "対象の依存関係を勧告の修正版へ更新し、新しい依存関係資料で確認する。"),
          location: { path: match.path, line: match.line } });
        break;
      }
    }
    if (results.length >= 100) return [...results, item("CVE", "残りのCVE候補", "unknown",
      "候補表示の上限に達しました。", "対象を分割して検証する。")];
  }
  return results.length ? results : [item("CVE", "依存関係と公開CVEの照合", "unknown",
    "対応する影響条件との一致はありません。対応外の版・未収録の勧告・実稼働の版は未確認です。",
    "対象パッケージの配布元勧告と実際に導入した版を確認する。")];
}

function redactedGitleaks(input: unknown, paths: Set<string>): Result[] {
  return array(input).slice(0, 100).flatMap((entry) => {
    const line = entry.StartLine;
    if (typeof entry.File !== "string" || !Number.isSafeInteger(line) || Number(line) < 1 ||
      typeof entry.RuleID !== "string" || !/^[a-z0-9-]{1,80}$/.test(entry.RuleID)) return [];
    const path = entry.File.replace(/^\.\//, "");
    if (!paths.has(path)) return [];
    return [{ ...item("Claude Code", "Gitleaksの資格情報候補", "unknown",
      "利用者が用意したローカルツールの報告です。値を表示せず、テスト用と実用の資格情報を区別してください。",
      "実用の資格情報なら値を共有せず失効し、秘密管理サービスに移す。"),
      location: { path, line: Number(line) } }];
  });
}

export async function scanProject(files: ProjectFile[], feed: unknown) {
  if (files.length > limits.entries) throw new Error("entry-limit");
  const candidates = files.flatMap(({ file, path }) => {
    const kind = classifyPath(path);
    return kind ? [{ file, path: path.split("/").slice(1).join("/") || file.name, ...kind }] : [];
  }).sort((a, b) => a.priority - b.priority);
  const rows = checkControls(undefined);
  const paths = new Set(candidates.map((candidate) => candidate.path));
  paths.delete("gitleaks-redacted.json");
  const inventories: Component[][] = [];
  let inventoryCount = 0;
  const languages = new Set<string>();
  const frameworks = new Set<string>();
  const lockKinds = new Set<string>();
  const packages = new Map<string, Package[]>();
  let packageCount = 0;
  let unsupported = 0;
  let skippedRules = 0;
  let unreadable = 0;
  let read = 0;
  let bytes = 0;
  let omitted = 0;
  for (const { file, path, name, priority } of candidates) {
    const dependency = /^(?:package-lock.json|npm-shrinkwrap.json|requirements.*\.txt|go.mod)$/i.test(name);
    if (read >= limits.files || file.size > (dependency ? limits.dependencyBytes : limits.fileBytes) || bytes + file.size > limits.bytes) {
      omitted++;
      continue;
    }
    read++;
    bytes += file.size;
    let content: string;
    try { content = await file.text(); } catch { unreadable++; continue; }
    const ext = name.split(".").at(-1)?.toLowerCase() ?? "";
    const language: Record<string, string> = { ts: "TypeScript", tsx: "TypeScript", js: "JavaScript", jsx: "JavaScript",
      mjs: "JavaScript", cjs: "JavaScript", py: "Python", rb: "Ruby", php: "PHP", go: "Go", rs: "Rust", java: "Java", cs: "C#" };
    if (priority > 0 && language[ext]) languages.add(language[ext]);
    if (/lock|shrinkwrap|\.sum$/i.test(name)) lockKinds.add(ext === "lock" ? "lock" : name.toLowerCase());
    let parsed: unknown;
    if (ext === "json") {
      try { parsed = JSON.parse(content); } catch { unsupported++; continue; }
    }
    if (name === "gitleaks-redacted.json") {
      const imported = redactedGitleaks(parsed, paths);
      if (!Array.isArray(parsed)) unsupported++;
      if (Array.isArray(parsed) && parsed.length > 100) skippedRules++;
      rows.push(...imported.slice(0, Math.max(0, 100 - rows.length)));
      if (imported.length && rows.length >= 100) skippedRules++;
      continue;
    }
    if (name === "package.json") {
      const pkg = record(parsed);
      const deps = { ...record(pkg.dependencies), ...record(pkg.devDependencies) };
      for (const [key, label] of [["next", "Next.js"], ["react", "React"], ["express", "Express"], ["vue", "Vue"]])
        if (Object.hasOwn(deps, key)) frameworks.add(label);
    }
    if (/^(?:requirements.*\.txt|pyproject\.toml)$/i.test(name)) {
      for (const framework of ["Django", "Flask", "FastAPI"]) {
        if (new RegExp(`(?:^|[\\"',\\s])${framework}(?:$|[\\s<=>~!\\[\\"',])`, "im").test(content)) frameworks.add(framework);
      }
    }
    if (name === "package-lock.json" || name === "npm-shrinkwrap.json") {
      rows.push({ ...checkLockfile(parsed), location: { path, line: propertyLine(content, "packages") } });
    }
    if (dependency) {
      const dependencies = collectPackages(name, path, content, parsed);
      if (!dependencies.length) unsupported++;
      for (const entry of dependencies) {
        if (packageCount >= 12000) { skippedRules++; break; }
        const key = `${entry.ecosystem}:${entry.name}`;
        const entries = packages.get(key) ?? [];
        entries.push(entry);
        packages.set(key, entries);
        packageCount++;
      }
      if (Object.keys(record(record(parsed).packages)).length > 10000) skippedRules++;
    } else if (/\.(?:lock|sum|toml|ya?ml|xml)$/.test(name) || (priority > 0 && !/^[cm]?[jt]sx?$/i.test(ext))) {
      unsupported++;
    }
    if (rows.length < 100) rows.push(...deploymentChecks(name, content, parsed, path));
    else skippedRules++;
    if (parsed && rows.length < 100) {
      const cloud = [
        ...checkCloudFormation(parsed).map((row) => ({ ...row, title: "EC2起動テンプレートのメタデータ保護",
          location: { path, line: propertyLine(content, row.title.split(" ／ ")[1] ?? "") } })),
        ...cloudStorage(parsed, path, content),
      ];
      if (cloud.length > 20) skippedRules++;
      rows.push(...cloud.slice(0, 20));
    }
    if (inventoryCount < 200) {
      const components = componentsFrom(name, content, parsed, path).slice(0, 200 - inventoryCount);
      if (components.length) {
        // Separate images and inventories may represent unrelated environments.
        if (/^Dockerfile(?:\.|$)/i.test(name)) inventories.push(...components.map((component) => [component]));
        else inventories.push(components);
        inventoryCount += components.length;
      }
    }
    if (/^[cm]?[jt]sx?$/i.test(ext)) {
      if (rows.length >= 100) skippedRules++;
      else {
        const findings = jsFlow(name, content, path);
        if (findings.length === 10) skippedRules++;
        rows.push(...findings);
      }
    }
  }
  rows.push(...(Array.isArray(feed) ? osvCves(feed, packages) : projectCves(feed, inventories)));
  return { rows, read, omitted, unsupported, unreadable, skippedRules, skipped: files.length - candidates.length,
    languages: [...languages], frameworks: [...frameworks], lockKinds: lockKinds.size, packageCount };
}
