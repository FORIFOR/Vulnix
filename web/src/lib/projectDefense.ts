import ts from "typescript";
import { parseAllDocuments } from "yaml";
import { inspectRuntimeFile, type PlannedCheck } from "./runtimePlan";
import { pythonFlow, type PythonFlowKind } from "./pythonFlow";
import { affects, collectPackages, compareVersions, propertyLine, sbomComponents, type Package, type Location } from "./projectPackages";
import { advisorySeverity, checkCloudFormation, checkControls, checkLockfile, record, type ResultLocation } from "./quickDefense";

export const limits = { entries: 12000, files: 180, timeMs: 30000, findings: 5000, fileBytes: 1024 * 1024, dependencyBytes: 4 * 1024 * 1024, bytes: 12 * 1024 * 1024 };
export type ProjectFile = { file: File; path: string };
type Result = ReturnType<typeof checkControls>[number];
type Component = { location?: Location; part: string; vendor: string; product: string; version: string };
const excluded = /^(?:\.|node_modules$|vendor$|dist$|build$|coverage$|target$|__pycache__$|secrets?$)/i;
const source = /\.(?:[cm]?[jt]s|[jt]sx|py|rb|php|go|rs|java|cs)$/i;
const sbomName = /(?:sbom|cyclonedx|spdx).*\.json$|(?:^|\.)bom\.json$/i;
const artifact = /^(?:gitleaks-redacted\.json|package(?:-lock)?\.json|npm-shrinkwrap\.json|requirements[^/]*\.txt|pyproject\.toml|poetry\.lock|uv\.lock|yarn\.lock|pnpm-lock\.yaml|go\.(?:mod|sum)|Cargo\.(?:toml|lock)|Gemfile(?:\.lock)?|composer\.(?:json|lock)|pom\.xml|Dockerfile(?:\.[\w-]+)?|.*(?:sbom|cloudformation|template|cfn|manifest|k8s|policy).*\.json)$/i;

export function classifyPath(path: string) {
  const parts = path.split("/");
  const name = parts.pop() ?? "";
  if (parts.length === 3 && parts[1] === ".github" && parts[2] === "workflows" && /\.ya?ml$/i.test(name))
    return { name, priority: 0 };
  if (name === "settings.json" && parts.length === 2 && parts[1] === ".claude") return { name, priority: 0 };
  if (parts.slice(1).some((part) => excluded.test(part)) ||
      excluded.test(name) || /(?:secret|credential|private.?key)|(?:\.min\.|\.generated\.)/i.test(name)) return null;
  if (sbomName.test(name) || artifact.test(name) || /\.(?:ya?ml|tf\.json|tf)$/i.test(name)) return { name, priority: 0 };
  if (source.test(name)) return { name, priority: /auth|access|db|sql|xml|render|route|handler|webhook|session|middleware/i.test(name) ? 1 : 2 };
  return null;
}

const PYTHON_FLOW: Record<PythonFlowKind, [string, string]> = {
  sql: ["外部入力からSQL実行", "値はプレースホルダーとパラメーターで渡し、SQL文字列に連結しない。"],
  command: ["外部入力からOSコマンド実行", "シェルを使わず引数の配列で実行し、許可した値だけを受け付ける。"],
  code: ["外部入力からコード評価", "eval・execを使わず、必要な値だけを型を決めて解釈する。"],
  template: ["外部入力からテンプレート・HTML生成", "利用者の値は自動エスケープされるテンプレート変数として渡す。"],
  xss: ["外部入力をそのままHTML応答", "応答はテンプレートの自動エスケープを通すか、html.escapeしてから返す。"],
  path: ["外部入力からファイルパス", "許可したディレクトリ内の固定名だけを解決し、パスの正規化後に範囲を確認する。"],
  ssrf: ["外部入力から外部通信先", "通信先は許可したホストの一覧から選び、内部アドレスへの接続を拒否する。"],
  deserialize: ["外部入力からデシリアライズ", "pickle等を使わずJSONなどの安全な形式で読み、yamlはSafeLoaderを使う。"],
  redirect: ["外部入力からリダイレクト先", "リダイレクト先は相対パスか許可したホストに限定する。"],
};

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
  if (path === ".claude/settings.json") {
    const permissions = record(spec.permissions);
    const broad = Array.isArray(permissions.allow) && permissions.allow.includes("Bash");
    const otherRules = [permissions.ask, permissions.deny].some((rule) =>
      rule !== undefined && (!Array.isArray(rule) || rule.length > 0));
    results.push({ ...item("Claude Code", "エージェントのツール権限", broad && !otherRules ? "action" : "unknown",
      broad && !otherRules ? "共有プロジェクト設定に、コマンドを限定しないシェル許可が記述されています。実際の許可は信頼状態と上位設定にも依存します。" :
        "共有プロジェクト設定だけではツールの実効権限を確定できません。",
      "共有設定の許可を必要な操作だけに限定し、利用者・管理設定と拒否ルールを合わせて確認する。"),
      location: { path, line: propertyLine(body, "allow") } });
  }
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
    let finalBase: { image: string; line: number } | undefined;
    for (const [i, line] of lines.entries()) {
      const base = line.match(/^\s*FROM\s+(?:--platform=\S+\s+)?([^\s]+)/i);
      if (base) {
        user = undefined;
        finalBase = { image: base[1], line: i + 1 };
      }
      const match = line.match(/^\s*USER\s+(\S+)\s*$/i);
      if (match) user = { value: match[1].split(":")[0], line: i + 1 };
    }
    const root = user && /^(root|0+)$/i.test(user.value);
    const nodeWithoutUser = !user && finalBase && /^(?:(?:docker\.io\/)?library\/)?node:[A-Za-z0-9_.-]+$/.test(finalBase.image);
    add("コンテナの既定ユーザー", root || nodeWithoutUser ? "action" : "unknown",
      root ? "最終ステージでrootユーザーを明示しています。" :
      nodeWithoutUser ? "最終ステージのNode公式イメージに対し非rootユーザーの指定がありません。配備側の上書きは未確認です。" :
        "実行時のユーザーと書き込み権限が未確認です。",
      "必要な権限だけを持つ実行ユーザーを設定し、実行時の上書きと書き込み可能な領域を確認する。",
      user?.line ?? finalBase?.line);
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

function configDocuments(name: string, content: string): unknown[] {
  if (/\.ya?ml$/i.test(name)) {
    const docs = parseAllDocuments(content, { schema: "core", uniqueKeys: true, merge: false });
    if (docs.length > 40 || docs.some((doc) => doc.errors.length || doc.warnings.length))
      throw new Error("unsupported YAML");
    // No aliases, custom tags, merge keys, includes or code evaluation.
    return docs.map((doc) => doc.toJS({ maxAliasCount: 0 }));
  }
  return [name.endsWith(".json") ? JSON.parse(content) : undefined];
}

function configurationChecks(input: unknown, path: string): Result[] {
  const config = record(input);
  const results: Result[] = [];
  if (path.startsWith(".github/workflows/")) {
    const jobs = Object.values(record(config.jobs)).map(record);
    const writeAll = config.permissions === "write-all" || jobs.some((job) => job.permissions === "write-all");
    if (writeAll) results.push({ ...item("ARTEX", "CIトークンの広い権限", "action",
      "ワークフローまたはジョブに書き込み全権限が明示されています。",
      "ジョブで必要な権限だけを付与し、プルリクエストや外部入力を受ける処理の権限を確認する。"), location: { path } });
    const uses = jobs.flatMap((job) => [job.uses, ...(Array.isArray(job.steps) ? job.steps.map((step) => record(step).uses) : [])]);
    const unpinned = uses.filter((value) => typeof value === "string" && !value.startsWith("./") &&
      /^[\w.-]+\/[\w./-]+@/.test(value) && !/@[a-f0-9]{40}$/i.test(value)).length;
    if (unpinned) results.push({ ...item("ARTEX", "CIアクションの更新範囲", "action",
      `コミットに固定されていないGitHub Actions参照が ${unpinned} 件あります。`,
      "信頼するアクションをレビューし、確認したコミットに固定する。"), location: { path } });
  }
  if (path.endsWith(".tf.json")) {
    const securityGroups = Object.values(record(record(config.resource).aws_security_group));
    for (const group of securityGroups) {
      const ingress = record(group).ingress;
      const rules = Array.isArray(ingress) ? ingress : [ingress];
      const publicAdmin = rules.map(record).some((rule) => {
        const all = [rule.cidr_blocks, rule.ipv6_cidr_blocks].some((list) =>
          Array.isArray(list) && (list.includes("0.0.0.0/0") || list.includes("::/0")));
        return all && (rule.protocol === "-1" || (rule.protocol === "tcp" &&
          typeof rule.from_port === "number" && typeof rule.to_port === "number" &&
          [22, 3389].some((port) => Number(rule.from_port) <= port && port <= Number(rule.to_port))));
      });
      if (publicAdmin) results.push({ ...item("ARTEX", "Terraformの管理ポート公開", "action",
        "Terraform JSONに管理ポートを全インターネットから許可する設定があります。適用済みかは未確認です。",
        "管理用の送信元を制限し、適用済みのルールも確認する。"), location: { path } });
    }
  }
  return results;
}

function componentsFrom(file: string, body: string, parsed: unknown, path: string): Component[] {
  if (/^Dockerfile(?:\.|$)/i.test(file)) {
    return [...body.matchAll(/^\s*FROM\s+(?:docker\.io\/library\/|library\/)?httpd:(\d+\.\d+\.\d+)\s*(?:$|#)/gim)]
      .map((match) => ({ part: "a", vendor: "apache", product: "http_server", version: match[1], location: { path, line: body.slice(0, match.index).split("\n").length } }));
  }
  const { rows, key } = sbomComponents(parsed);
  const line = propertyLine(body, key);
  return rows.flatMap((value) => {
    const match = typeof value.cpe === "string" && value.cpe.match(/^cpe:2\.3:([aho]):([\w.-]+):([\w.-]+):(-|\d+(?:\.\d+){1,7})(?::\*){7}$/);
    return match ? [{ part: match[1], vendor: match[2], product: match[3], version: match[4], location: { path, line } }] : [];
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
    rule.criteria.match(/^cpe:2\.3:([aho]):([\w.-]+):([\w.-]+):([*-]|\d+(?:\.\d+){1,7})(?::\*){7}$/);
  if (!parsed || typeof rule.vulnerable !== "boolean") return null;
  const same = inventory.filter((c) => c.part === parsed[1] && c.vendor === parsed[2] && c.product === parsed[3]);
  const bounds = [
    ["versionStartIncluding", (n: number) => n >= 0], ["versionStartExcluding", (n: number) => n > 0],
    ["versionEndIncluding", (n: number) => n <= 0], ["versionEndExcluding", (n: number) => n < 0],
  ] as const;
  for (const c of same) {
    if (c.version === "-" || parsed[4] === "-") {
      if (rule.vulnerable === false && c.version === parsed[4] && !bounds.some(([key]) => key in rule)) return true;
      continue;
    }
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
      "配布元の勧告で導入済みビルド、修正の有無、影響条件を照合し、必要な更新を適用する。"), location, severity: advisorySeverity(cve.severity) });

  }
  return results.length ? results : [item("CVE", "公開CVEとの照合", "unknown",
    "同梱または選択したカタログで照合できる製品・構成の候補がありません。依存関係名だけでは製品を特定できません。",
    "稼働中の製品と版を確認し、必要に応じてCPE付きのCycloneDXと最新のNVDカタログを選ぶ。")];
}

function osvCves(feed: unknown, packages: Map<string, Package[]>, deadline: number, markIncomplete: () => void) {
  const results: Result[] = [];
  let retained = 0;
  for (const osv of array(feed)) {
    if (performance.now() >= deadline || retained >= 12000) { markIncomplete(); break; }
    if (osv.withdrawn) continue;
    const ids = [...new Set([...(Array.isArray(osv.aliases) ? osv.aliases : []), osv.id].filter(
      (value): value is string => typeof value === "string" && /^CVE-\d{4}-\d{4,}$/.test(value)))];
    if (!ids.length) continue;
    const locations = new Map<string, ResultLocation>();
    for (const affected of array(osv.affected)) {
      const pkg = record(affected.package);
      if (!["npm", "PyPI", "Go"].includes(String(pkg.ecosystem)) || typeof pkg.name !== "string") continue;
      const name = pkg.ecosystem === "PyPI" ? pkg.name.toLowerCase().replace(/[-_.]+/g, "-") : pkg.name;
      for (const match of packages.get(`${pkg.ecosystem}:${name}`) ?? []) {
        if (!affects(match.version, match.ecosystem, affected)) continue;
        const fixed = [...new Set(array(affected.ranges).filter((range) => affects(match.version, match.ecosystem, { ranges: [range] }))
          .flatMap((range) => array(range.events).flatMap((event) => typeof event.fixed === "string" &&
            (compareVersions(match.ecosystem, match.version, event.fixed) ?? 0) < 0 &&
            !affects(event.fixed, match.ecosystem, affected) ? [event.fixed] : [])))];
        const location = { path: match.path, line: match.line, dependency: match.name, ecosystem: match.ecosystem, version: match.version, fixed };
        const key = locationIdentity(location);
        if (locations.has(key)) continue;
        if (retained + locations.size >= 12000) { markIncomplete(); break; }
        locations.set(key, location);
      }
    }
    if (!locations.size) continue;
    const rows = [...locations.values()];
    retained += rows.length;
    for (const id of ids) results.push({ ...item("CVE", id, "action",
      "依存関係資料の版が勧告の影響条件に一致しました。実行環境の版と到達性は未確認です。",
      "影響する依存関係を勧告の修正版へ更新し、新しい依存関係資料で照合する。"),
      location: rows[0], locations: rows, severity: advisorySeverity(record(osv.database_specific).severity) });
  }
  return results.length ? results : [item("CVE", "依存関係と公開CVEの照合", "unknown",
    "対応する影響条件との一致はありません。対応外の版・未収録の勧告・実稼働の版は未確認です。",
    "対象パッケージの配布元勧告と実際に導入した版を確認する。")];
}

function locationIdentity(location: ResultLocation) {
  return JSON.stringify([location.path, location.line, location.dependency, location.ecosystem, location.version]);
}

export type CatalogLookup = (packageKeys: string[], cpeKeys: string[], deadline: number) => Promise<{
  osv: unknown[]; vulnerabilities: unknown[]; incomplete: boolean;
}>;

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

export type ScanProgress = {
  eligible: number; processed: number; excluded: number; omitted: number; unreadable: number; read: number;
  batches: number; pendingPaths: string[];
};

export async function scanProject(files: ProjectFile[], feed: unknown, onProgress?: (value: ScanProgress) => void, lookupCatalog?: CatalogLookup) {
  const deadline = performance.now() + limits.timeMs;
  if (files.length > limits.entries) throw new Error("entry-limit");
  const seenPaths = new Set<string>();
  const candidates = files.flatMap(({ file, path }) => {
    if (seenPaths.has(path)) return [];
    seenPaths.add(path);
    const kind = classifyPath(path);
    return kind ? [{ file, path: path.split("/").slice(1).join("/") || file.name, ...kind }] : [];
  }).sort((a, b) => a.priority - b.priority);
  const rows: Result[] = [];
  const findings = new Set<string>();
  const retained = { action: 0, other: 0 };
  let unretained = 0;
  function addRows(...incoming: Result[]) {
    for (const row of incoming) {
      const key = JSON.stringify([row.category, row.title, row.status, row.location?.path, row.location?.line, row.evidence]);
      if (findings.has(key)) continue;
      const tier = row.status === "action" ? "action" : "other";
      if (retained[tier] >= limits.findings / 2) { unretained++; continue; }
      findings.add(key);
      retained[tier]++;
      rows.push(row);
    }
  }
  addRows(...checkControls(undefined).map((row) => ({ ...row,
    evidence: "この項目を判定できる実効設定やレビュー済みテストの結果は、フォルダ診断からは取得していません。",
  })));
  const paths = new Set(candidates.map((candidate) => candidate.path));
  paths.delete("gitleaks-redacted.json");
  const runtimePlan = new Map<PlannedCheck["id"], PlannedCheck>();
  const inventories: Component[][] = [];
  let inventoryCount = 0;
  const languages = new Set<string>();
  const frameworks = new Set<string>();
  const lockKinds = new Set<string>();
  const packages = new Map<string, Package[]>();
  let packageCount = 0;
  let unsupported = 0;
  const coverage = { source: 0, noSourceRules: 0, parseFailed: 0, packageFiles: 0,
    unresolvedDependencies: 0, sbomWithoutPackages: 0, osvAdvisories: 0, nvdAdvisories: 0, pythonFlow: 0 };
  let skippedRules = 0;
  let unreadable = 0;
  let read = 0;
  let batchBytes = 0;
  let batchFiles = 0;
  let batches = 0;
  let omitted = 0;
  let processed = 0;
  const incomplete: { path: string; reason: string }[] = [];
  const excluded = files.length - candidates.length;
  const progress = () => ({ eligible: candidates.length, processed, excluded, omitted, unreadable, read, batches,
    pendingPaths: candidates.slice(processed, processed + 10).map(({ path }) => path) });
  onProgress?.(progress());
  for (const { file, path, name, priority } of candidates) {
    if (performance.now() >= deadline) break;
    const dependency = sbomName.test(name) || /^(?:package-lock\.json|npm-shrinkwrap\.json|requirements.*\.txt|go\.mod)$/i.test(name);
    const tooLarge = file.size > (dependency ? limits.dependencyBytes : limits.fileBytes);
    const bytesToRead = tooLarge ? 0 : file.size;
    if (batchFiles === limits.files || batchBytes + bytesToRead > limits.bytes || batches === 0) {
      batches++;
      batchBytes = 0;
      batchFiles = 0;
    }
    if (processed > 0 && (batchFiles === 0 || processed % 10 === 0)) onProgress?.(progress());
    processed++;
    batchFiles++;
    batchBytes += bytesToRead;

    if (tooLarge) {
      omitted++;
      if (incomplete.length < 100) incomplete.push({ path, reason: "ファイル上限" });
      continue;
    }
    read++;
    let content: string;
    try { content = await file.text(); } catch {
      unreadable++;
      if (incomplete.length < 100) incomplete.push({ path, reason: "読取失敗" });
      continue;
    }
    const notParsed = (reason: string) => {
      unsupported++;
      if (incomplete.length < 100) incomplete.push({ path, reason });
    };
    const ext = name.split(".").at(-1)?.toLowerCase() ?? "";
    const language: Record<string, string> = { ts: "TypeScript", tsx: "TypeScript", js: "JavaScript", jsx: "JavaScript",
      mjs: "JavaScript", cjs: "JavaScript", py: "Python", rb: "Ruby", php: "PHP", go: "Go", rs: "Rust", java: "Java", cs: "C#" };
    if (priority > 0 && language[ext]) languages.add(language[ext]);
    if (/lock|shrinkwrap|\.sum$/i.test(name)) lockKinds.add(ext === "lock" ? "lock" : name.toLowerCase());
    let documents: unknown[];
    try { documents = configDocuments(name, content); } catch { coverage.parseFailed++; notParsed("構文エラーまたは未対応の記法"); continue; }
    const parsed = documents[0];
    const manifestDependencies = name === "package.json" ? Object.keys(record(record(parsed).dependencies)) :
      /^requirements[^/]*\.txt$/i.test(name) ? content.split("\n").flatMap((line) => {
        const dependency = /^\s*([a-z0-9_.-]+)(?:\[|[ \t]*[<=>~!]|\s*$)/i.exec(line);
        return dependency ? [dependency[1]] : [];
      }) : [];
    inspectRuntimeFile(runtimePlan, path, content, manifestDependencies);
    if (name === "gitleaks-redacted.json") {
      const imported = redactedGitleaks(parsed, paths);
      if (!Array.isArray(parsed)) notParsed("対応する監査記録の形式ではない");
      if (Array.isArray(parsed) && parsed.length > 100) skippedRules++;
      addRows(...imported);
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
      addRows({ ...checkLockfile(parsed), location: { path, line: propertyLine(content, "packages") } });
    }
    if (dependency) {
      const dependencies = collectPackages(name, path, content, parsed);
      if (dependencies.length) coverage.packageFiles++;
      else if (!sbomName.test(name) || !componentsFrom(name, content, parsed, path).length)
        notParsed(sbomName.test(name) ? "対応する版・識別子のあるSBOM項目なし" : "照合可能な固定版なし");
      if (/^requirements.*\.txt$/i.test(name)) {
        const selectedLines = new Set(dependencies.map((entry) => entry.line));
        const unresolved = content.split(/\r?\n/).filter((line, index) =>
          /^\s*(?:[a-z0-9_.]|-(?:r|c)\s|--(?:requirement|constraint)\b)/i.test(line) &&
          !selectedLines.has(index + 1)).length;
        coverage.unresolvedDependencies += unresolved;
        if (unresolved && dependencies.length && incomplete.length < 100)
          incomplete.push({ path, reason: `固定版を特定できない依存指定が ${unresolved} 行` });
      }
      if (sbomName.test(name)) {
        const unmatched = Math.max(0, sbomComponents(parsed).total - dependencies.length);
        coverage.sbomWithoutPackages += unmatched;
        if (unmatched) {
          skippedRules++;
          if (dependencies.length && incomplete.length < 100)
            incomplete.push({ path, reason: `パッケージ名と固定版を照合できないSBOM項目が ${unmatched} 件（製品識別子での照合は別）` });
        }
      }
      for (const entry of dependencies) {
        if (packageCount >= 12000) { skippedRules++; break; }
        const key = `${entry.ecosystem}:${entry.name}`;
        const entries = packages.get(key) ?? [];
        entries.push(entry);
        packages.set(key, entries);
        packageCount++;
      }
      if (Object.keys(record(record(parsed).packages)).length > 10000) skippedRules++;
    } else if (priority > 0 && ext === "py") {
      coverage.source++;
      coverage.pythonFlow++;
      const flows = pythonFlow(content);
      if (flows.length === 20) skippedRules++;
      addRows(...flows.map((flow) => ({
        ...item("Claude Code", PYTHON_FLOW[flow.kind][0], "action",
          `ソースの${flow.line}行目。関数 ${flow.func} の中で、要求データが ${flow.sink} に渡る経路を静的に確認しました（同じ関数内の追跡。実行時の到達性・入力検証は未確認）。`,
          PYTHON_FLOW[flow.kind][1]),
        location: { path, line: flow.line },
      })));
    } else if (priority > 0 && !/^[cm]?[jt]sx?$/i.test(ext)) {
      coverage.noSourceRules++;
      notParsed("この言語にはデータフロー検査がない（共通検査のみ）");
    } else if (/\.(?:lock|sum|toml|tf|xml)$/.test(name)) {
      notParsed("この形式から依存関係の固定版や設定を抽出できない");
    }
    for (const document of documents) {
      addRows(...deploymentChecks(name, content, document, path), ...configurationChecks(document, path));
    }
    if (documents.some(Boolean)) {
      const cloud = [
        ...documents.flatMap(checkCloudFormation).map((row) => ({ ...row, title: "EC2起動テンプレートのメタデータ保護",
          location: { path, line: propertyLine(content, row.title.split(" ／ ")[1] ?? "") } })),
        ...documents.flatMap((document) => cloudStorage(document, path, content)),
      ];
      if (cloud.length > 20) skippedRules++;
      addRows(...cloud.slice(0, 20));
    }
    if (inventoryCount < 200) {
      const found = componentsFrom(name, content, parsed, path);
      const components = found.slice(0, 200 - inventoryCount);
      if (found.length > components.length) skippedRules++;
      if (components.length) {
        // Separate images and inventories may represent unrelated environments.
        if (/^Dockerfile(?:\.|$)/i.test(name)) inventories.push(...components.map((component) => [component]));
        else inventories.push(components);
        inventoryCount += components.length;
      }
    } else if (componentsFrom(name, content, parsed, path).length) skippedRules++;
    if (/^[cm]?[jt]sx?$/i.test(ext)) {
      coverage.source++;
      const findings = jsFlow(name, content, path);
      if (findings.length === 10) skippedRules++;
      addRows(...findings);
    }
  }
  let catalogIncomplete = false;
  let indexed: Awaited<ReturnType<CatalogLookup>> | undefined;
  if (lookupCatalog) {
    const cpes = [...new Set(inventories.flatMap((inventory) => inventory.map(({ part, vendor, product }) => `cpe:${part}:${vendor}:${product}`)))];
    try {
      indexed = await lookupCatalog([...packages.keys()], cpes, deadline);
      catalogIncomplete = indexed.incomplete;
    } catch { catalogIncomplete = true; }
  }
  const parsedFeed = record(feed);
  const osvFeed = Array.isArray(feed) ? feed : parsedFeed.osv;
  const nvdEntries = new Map([...array(parsedFeed.vulnerabilities), ...array(indexed?.vulnerabilities)].map((entry) => [record(entry.cve).id, entry]));
  const nvdRows = projectCves({ vulnerabilities: [...nvdEntries.values()] }, inventories);
  const osvEntries = new Map([...array(osvFeed), ...array(indexed?.osv)].map((entry) => [entry.id, entry]));
  coverage.nvdAdvisories = nvdEntries.size;
  coverage.osvAdvisories = osvEntries.size;
  const osvRows = osvEntries.size ? osvCves([...osvEntries.values()], packages, deadline, () => { catalogIncomplete = true; }) : [];
  const matched = new Map<string, Result>();
  for (const row of [...nvdRows, ...osvRows]) {
    if (!row.title.startsWith("CVE-")) continue;
    const other = matched.get(row.title);
    if (!other) { matched.set(row.title, row); continue; }
    const merged = new Map<string, ResultLocation>();
    for (const location of [...(other.locations ?? (other.location ? [other.location] : [])),
      ...(row.locations ?? (row.location ? [row.location] : []))]) {
      const key = locationIdentity(location);
      const previous = merged.get(key);
      merged.set(key, previous ? { ...location, fixed: [...new Set([...(previous.fixed ?? []), ...(location.fixed ?? [])])] } : location);
    }
    const chosen = row.status === "action" && other.status !== "action"
      ? { ...row, evidence: `${row.evidence} NVDにも対応する候補があります。` } : other;
    matched.set(row.title, { ...chosen, severity: chosen.severity ?? other.severity ?? row.severity,
      locations: [...merged.values()] });
  }
  let retainedCveLocations = 0;
  for (const row of matched.values()) {
    const available = Math.max(0, 12000 - retainedCveLocations);
    if (row.locations && row.locations.length > available) {
      catalogIncomplete = true;
      if (!available) { unretained++; continue; }
      row.locations = row.locations.slice(0, available);
    }
    retainedCveLocations += row.locations?.length ?? 1;
    addRows(row);
  }
  // Preserve evidence of an unmatched catalog even when the other catalog matched.
  if (!Array.isArray(feed)) addRows(...nvdRows.filter((row) => !row.title.startsWith("CVE-")));
  addRows(...osvRows.filter((row) => !row.title.startsWith("CVE-")));
  rows.sort((a, b) => Number(b.status === "action") - Number(a.status === "action"));
  const scanProgress = progress();
  onProgress?.(scanProgress);
  for (const { path } of candidates.slice(processed, processed + 100 - incomplete.length)) {
    incomplete.push({ path, reason: "時間上限で未処理" });
  }
  return { rows, read, omitted, unsupported, unreadable, skippedRules, skipped: excluded,
    pending: candidates.length - processed, incomplete, unretained, scanProgress, catalogIncomplete, runtimePlan: [...runtimePlan.values()],
    languages: [...languages], frameworks: [...frameworks], lockKinds: lockKinds.size, packageCount, coverage };
}
