import ts from "typescript";
import { checkCloudFormation, checkControls, checkLockfile, record } from "./quickDefense";

export const limits = { entries: 12000, files: 180, fileBytes: 256 * 1024, bytes: 6 * 1024 * 1024 };
export type ProjectFile = { file: File; path: string };
type Result = ReturnType<typeof checkControls>[number];
type Component = { part: string; vendor: string; product: string; version: string };
const excluded = /^(?:\.|node_modules$|vendor$|dist$|build$|coverage$|target$|data[^/]*$|__pycache__$|secrets?$)/i;
const source = /\.(?:[cm]?[jt]s|[jt]sx|py|rb|php|go|rs|java|cs)$/i;
const artifact = /^(?:package(?:-lock)?\.json|npm-shrinkwrap\.json|requirements[^/]*\.txt|pyproject\.toml|poetry\.lock|uv\.lock|yarn\.lock|pnpm-lock\.yaml|go\.(?:mod|sum)|Cargo\.(?:toml|lock)|Gemfile(?:\.lock)?|composer\.(?:json|lock)|pom\.xml|Dockerfile(?:\.[\w-]+)?|.*(?:sbom|cloudformation|template|cfn).*\.json)$/i;

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

function jsFlow(name: string, input: string): Result[] {
  const tree = ts.createSourceFile(name, input, ts.ScriptTarget.Latest, true);
  const results: Result[] = [];
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
          if (ts.isIdentifier(decl.name) && decl.initializer) bindings.set(decl.name.text, trace(decl.initializer, bindings));
        }
      }
      if (ts.isExpressionStatement(statement)) {
        const expr = statement.expression;
        if (ts.isBinaryExpression(expr) && ts.isPropertyAccessExpression(expr.left) &&
          ["innerHTML", "textContent"].includes(expr.left.name.text) && expr.operatorToken.kind === ts.SyntaxKind.EqualsToken) {
          const fromRequest = trace(expr.right, bindings);
          const asText = expr.left.name.text === "textContent";
          if (asText && !fromRequest) continue;
          results.push(item("Claude Code", "外部入力とHTML出力", fromRequest ? (asText ? "confirmed" : "action") : "unknown",
            `ソースの${line(expr)}行目。 ${asText ? "要求データをテキストとして書き込む経路です。" :
              fromRequest ? "要求データからHTML書き込みへの直接経路を確認しました。" : "HTML書き込みの入力元を確定できません。"}`,
            "文字列はテキストとして描画し、HTMLが必要な場合はサニタイザーを通す。"));
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

function cloudStorage(input: unknown): Result[] {
  return Object.values(record(record(input).Resources)).flatMap((resource) => {
    const bucket = record(resource);
    if (bucket.Type !== "AWS::S3::Bucket") return [];
    const policy = record(record(bucket.Properties).PublicAccessBlockConfiguration);
    const complete = ["BlockPublicAcls", "IgnorePublicAcls", "BlockPublicPolicy", "RestrictPublicBuckets"]
      .every((field) => policy[field] === true);
    return [item("Claude Code", "ストレージの公開防止", complete ? "confirmed" : "unknown",
      complete ? "S3バケットのテンプレートに公開を防ぐ4設定が明示されています。" :
        "テンプレートだけでは公開を防ぐ設定を確認できません。アカウント側の設定や稼働状態も確認してください。",
      "公開不要のバケットでは公開アクセスのブロックを有効にし、組織・アカウント・バケット設定を照合する。")];
  });
}

function componentsFrom(file: string, body: string, parsed: unknown): Component[] {
  if (/^Dockerfile(?:\.|$)/i.test(file)) {
    return [...body.matchAll(/^\s*FROM\s+(?:docker\.io\/library\/|library\/)?httpd:(\d+\.\d+\.\d+)\s*(?:$|#)/gim)]
      .map((match) => ({ part: "a", vendor: "apache", product: "http_server", version: match[1] }));
  }
  const sbom = record(parsed);
  if (sbom.bomFormat !== "CycloneDX" || !Array.isArray(sbom.components)) return [];
  return sbom.components.slice(0, 200).flatMap((value: unknown) => {
    const match = typeof record(value).cpe === "string" &&
      String(record(value).cpe).match(/^cpe:2\.3:([aho]):([\w.-]+):([\w.-]+):(\d+(?:\.\d+){1,7})(?::\*){7}$/);
    return match ? [{ part: match[1], vendor: match[2], product: match[3], version: match[4] }] : [];
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
    for (const inventory of inventories) for (const config of array(cve.configurations)) {
      if (config.negate === true) continue;
      const nodes = array(config.nodes).map((node) => {
        const rules = array(node.cpeMatch);
        const identified = rules.map((rule) => matches(rule, inventory) === true);
        const positive = rules.some((rule, i) => rule.vulnerable === true && identified[i]);
        if (positive) candidate = true;
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
    if (candidate) results.push(item("CVE", cve.id, "unknown", applicable ?
      "プロジェクト資料にカタログ上の製品・版・構成条件の組み合わせがあります。実稼働構成と配布元の修正は未確認です。" :
      "製品・版は候補に一致します。必要な構成条件の一部を確認できません。",
      "配布元の勧告で導入済みビルド、修正の有無、影響条件を照合し、必要な更新を適用する。"));
    if (results.length >= 100) {
      results.push(item("CVE", "残りのCVE候補", "unknown", "候補表示の上限に達しました。", "対象を分割して検証する。"));
      break;
    }
  }
  return results.length ? results : [item("CVE", "公開CVEとの照合", "unknown",
    "同梱または選択したカタログで照合できる製品・構成の候補がありません。依存関係名だけでは製品を特定できません。",
    "稼働中の製品と版を確認し、必要に応じてCPE付きのCycloneDXと最新のNVDカタログを選ぶ。")];
}

function npmDependencies(input: unknown) {
  const lock = record(input);
  if (lock.lockfileVersion !== 2 && lock.lockfileVersion !== 3) return [];
  return Object.entries(record(lock.packages)).flatMap(([path, entry]) => {
    const dependency = record(entry);
    const match = path.match(/(?:^|\/)node_modules\/((?:@[a-z0-9._-]+\/)?[a-z0-9._-]+)$/);
    if (!match || dependency.link === true || (dependency.name && dependency.name !== match[1]) ||
        typeof dependency.version !== "string" || dependency.version.length > 80 ||
        typeof dependency.integrity !== "string" || typeof dependency.resolved !== "string" ||
        !/^https:\/\//i.test(dependency.resolved)) return [];
    return [[match[1], dependency.version] as const];
  });
}

function osvCves(feed: unknown, packages: Map<string, Set<string>>) {
  const results: Result[] = [];
  for (const osv of array(feed)) {
    if (osv.withdrawn) continue;
    const id = (Array.isArray(osv.aliases) ? [...osv.aliases, osv.id] : [osv.id])
      .find((value) => typeof value === "string" && /^CVE-\d{4}-\d{4,}$/.test(value));
    if (!id) continue;
    for (const affected of array(osv.affected)) {
      const pkg = record(affected.package);
      if (pkg.ecosystem !== "npm" || typeof pkg.name !== "string" || !Array.isArray(affected.versions)) continue;
      const versions = packages.get(pkg.name);
      if (versions && affected.versions.some((version) => typeof version === "string" && versions.has(version))) {
        results.push(item("CVE", id, "action",
          "npmロックファイルの固定版が、選択した勧告の影響版一覧に一致しました。稼働環境での利用状況は未確認です。",
          "対象の依存関係を勧告の修正版へ更新し、新しいロックファイルで確認する。"));
        break;
      }
    }
    if (results.length >= 100) return [...results, item("CVE", "残りのCVE候補", "unknown",
      "候補表示の上限に達しました。", "対象を分割して検証する。")];
  }
  return results.length ? results : [item("CVE", "npm依存関係と公開CVEの照合", "unknown",
    "明記された影響版との一致はありません。範囲だけの勧告、未収録の勧告、実稼働の版は未確認です。",
    "対象パッケージの配布元勧告と実際に導入した版を確認する。")];
}

export async function scanProject(files: ProjectFile[], feed: unknown) {
  if (files.length > limits.entries) throw new Error("entry-limit");
  const candidates = files.flatMap(({ file, path }) => {
    const kind = classifyPath(path);
    return kind ? [{ file, ...kind }] : [];
  }).sort((a, b) => a.priority - b.priority);
  const rows = checkControls(undefined);
  const inventories: Component[][] = [];
  let inventoryCount = 0;
  const languages = new Set<string>();
  const frameworks = new Set<string>();
  const lockKinds = new Set<string>();
  const packages = new Map<string, Set<string>>();
  let read = 0;
  let bytes = 0;
  let omitted = 0;
  for (const { file, name, priority } of candidates) {
    if (read >= limits.files || file.size > limits.fileBytes || bytes + file.size > limits.bytes) {
      omitted++;
      continue;
    }
    read++;
    bytes += file.size;
    let content: string;
    try { content = await file.text(); } catch { omitted++; continue; }
    const ext = name.split(".").at(-1)?.toLowerCase() ?? "";
    const language: Record<string, string> = { ts: "TypeScript", tsx: "TypeScript", js: "JavaScript", jsx: "JavaScript",
      mjs: "JavaScript", cjs: "JavaScript", py: "Python", rb: "Ruby", php: "PHP", go: "Go", rs: "Rust", java: "Java", cs: "C#" };
    if (priority > 0 && language[ext]) languages.add(language[ext]);
    if (/lock|shrinkwrap|\.sum$/i.test(name)) lockKinds.add(ext === "lock" ? "lock" : name.toLowerCase());
    let parsed: unknown;
    if (ext === "json") {
      try { parsed = JSON.parse(content); } catch { omitted++; continue; }
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
      rows.push(checkLockfile(parsed));
      for (const [name, version] of npmDependencies(parsed)) {
        const versions = packages.get(name) ?? new Set<string>();
        versions.add(version);
        packages.set(name, versions);
      }
    }
    if (parsed && rows.length < 100) {
      rows.push(...checkCloudFormation(parsed).map((row) => ({ ...row, title: "EC2起動テンプレートのメタデータ保護" })).slice(0, 20));
      rows.push(...cloudStorage(parsed).slice(0, 20));
    }
    if (inventoryCount < 200) {
      const components = componentsFrom(name, content, parsed).slice(0, 200 - inventoryCount);
      if (components.length) {
        // Separate images and inventories may represent unrelated environments.
        if (/^Dockerfile(?:\.|$)/i.test(name)) inventories.push(...components.map((component) => [component]));
        else inventories.push(components);
        inventoryCount += components.length;
      }
    }
    if (/^[cm]?[jt]sx?$/i.test(ext) && rows.length < 100) rows.push(...jsFlow(name, content));
  }
  rows.push(...(Array.isArray(feed) ? osvCves(feed, packages) : projectCves(feed, inventories)));
  return { rows, read, omitted, skipped: files.length - candidates.length,
    languages: [...languages], frameworks: [...frameworks], lockKinds: lockKinds.size, npmPackages: packages.size };
}
