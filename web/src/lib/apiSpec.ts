// A2B (app -> backend API) check candidates from an OpenAPI / Swagger file or a project's route
// definitions. Runs in the browser; nothing is sent anywhere. A definition says which routes
// exist and what they declare - never who owns a record or how the server really decides -
// so every candidate lists what is still unknown, and nothing here is a verdict.
import { parse as parseYaml } from "yaml";

export type ApiKind = "auth" | "cross_account" | "cross_tenant" | "admin_function" | "sensitive";
export type ApiEndpoint = {
  method: string; path: string; source: string;
  /** "none": the definition declares no authentication; "declared": it declares some; "unknown": it does not say. */
  auth: "none" | "declared" | "unknown";
  admin: boolean; orgParam: string | null; idParam: string | null; sensitive: string[];
  /** Where a "declared" came from, or why a route behind an app-wide check is still unknown. */
  authBasis?: "route" | "middleware" | "middleware_excluded" | "middleware_conditional";
};
export type ApiCandidate = { kind: ApiKind; endpoint: ApiEndpoint; reason: string; unknown: string[] };
export type ApiAnalysis = { title: string; host: string | null; endpoints: ApiEndpoint[]; candidates: ApiCandidate[]; notes: string[] };

export const KIND_LABEL: Record<ApiKind, string> = {
  auth: "APIの認証", cross_account: "データへのアクセス権限", cross_tenant: "組織・ユーザー間の分離",
  admin_function: "管理者専用機能の権限", sensitive: "機密情報の取り扱い",
};
/** Kinds the L2 rule engine can check at run time (with test accounts, after approval). */
export const RUNTIME_KINDS = ["cross_account", "cross_tenant", "admin_function"] as const;

const METHODS = ["get", "put", "post", "delete", "patch"];
const ORG = /^(?:org|orgs|organization|organisation|tenant|team|workspace|company|account)(?:_?id)?$/i;
const PUBLIC = /(?:^|\/)(?:health|healthz|ready|status|login|logout|signin|signup|register|token|oauth|docs|openapi|swagger)(?:\/|$|\.)/i;
const SENSITIVE = /(?:password|passwd|secret|api_?key|token|ssn|social_security|credit_?card|card_?number|cvv|private_?key)/i;
const ADMIN_PATH = /(?:^|\/)(?:admin|admins|internal|manage|management|superuser)(?:\/|$)/i;

type Obj = Record<string, unknown>;
const obj = (v: unknown): Obj => (v && typeof v === "object" && !Array.isArray(v) ? v as Obj : {});

function resolve(root: Obj, node: unknown, depth = 0): Obj {
  const n = obj(node);
  const ref = typeof n.$ref === "string" ? n.$ref : null;
  if (!ref || depth > 8 || !ref.startsWith("#/")) return n;
  let cur: unknown = root;
  for (const part of ref.slice(2).split("/")) cur = obj(cur)[part.replace(/~1/g, "/").replace(/~0/g, "~")];
  return resolve(root, cur, depth + 1);
}

function fields(root: Obj, schema: unknown, depth = 0, seen = new Set<unknown>()): string[] {
  const s = resolve(root, schema);
  if (depth > 5 || seen.has(s)) return [];
  seen.add(s);
  const own = Object.keys(obj(s.properties));
  const nested = [...Object.values(obj(s.properties)), s.items, ...(Array.isArray(s.allOf) ? s.allOf : [])]
    .flatMap((child) => fields(root, child, depth + 1, seen));
  return [...own, ...nested];
}

function candidates(e: ApiEndpoint): ApiCandidate[] {
  const out: ApiCandidate[] = [];
  const owner = "所有者・組織の判定条件（定義からは分からない）";
  const data = "試験用アカウントと試験データ";
  if (e.auth === "none" && !PUBLIC.test(e.path))
    out.push({ kind: "auth", endpoint: e, reason: "定義上、認証なしで呼べる", unknown: ["公開してよいAPIか（利用者の確認が必要）"] });
  if (e.auth === "unknown")
    out.push({ kind: "auth", endpoint: e, reason: e.authBasis === "middleware_excluded"
      ? "アプリ全体の認証ミドルウェアの対象外と読める（除外されているか、確認されるパスに含まれない）"
      : e.authBasis === "middleware_conditional"
        ? "アプリ全体の認証ミドルウェアが、認証情報の無い要求や一部のパスだけを確認する書き方で、このルートが確認されるか読み取れない"
        : "認証の有無を定義から読み取れない", unknown: ["実装上の認証の有無"] });
  if (e.idParam && !e.admin)
    out.push({ kind: "cross_account", endpoint: e, reason: `資源を識別するパラメーター {${e.idParam}} がある`, unknown: [owner, data] });
  if (e.orgParam)
    out.push({ kind: "cross_tenant", endpoint: e, reason: `組織を識別するパラメーター {${e.orgParam}} がある`, unknown: [owner, data] });
  if (e.admin)
    out.push({ kind: "admin_function", endpoint: e, reason: "管理者向けと読める（パス・タグ・役割の宣言）", unknown: ["必要な役割（定義の宣言と実装が一致するか）", data] });
  if (e.sensitive.length)
    out.push({ kind: "sensitive", endpoint: e, reason: `応答に ${e.sensitive.slice(0, 4).join("・")} を含む`, unknown: ["実際に値が返るか・マスクされるか"] });
  return out;
}

function params(path: string): string[] {
  return [...path.matchAll(/\{([^}]+)\}|<(?:[a-z]+:)?([A-Za-z_]\w*)>|:([A-Za-z_]\w*)/g)].map((m) => m[1] ?? m[2] ?? m[3]);
}

function endpoint(method: string, path: string, source: string, auth: ApiEndpoint["auth"], adminHint: boolean,
  sensitive: string[] = []): ApiEndpoint {
  const ps = params(path);
  const org = ps.find((p) => ORG.test(p)) ?? null;
  const last = ps.filter((p) => p !== org).at(-1) ?? null;
  // a normalised "{param}" path, so the UI shows one form whatever the framework wrote
  const norm = path.replace(/<(?:[a-z]+:)?([A-Za-z_]\w*)>/g, "{$1}").replace(/:([A-Za-z_]\w*)/g, "{$1}");
  return { method: method.toUpperCase(), path: norm, source, auth, admin: adminHint || ADMIN_PATH.test(path),
    orgParam: org, idParam: last, sensitive: [...new Set(sensitive.filter((f) => SENSITIVE.test(f)))] };
}

/** OpenAPI 3 / Swagger 2, JSON or YAML. */
export function analyzeSpec(text: string, fileName: string): ApiAnalysis {
  let root: Obj;
  try {
    root = obj(/^\s*\{/.test(text) ? JSON.parse(text) : parseYaml(text, { maxAliasCount: 50 }));
  } catch {
    throw new Error("API 定義を JSON または YAML として読めません");
  }
  if (!root.openapi && !root.swagger) throw new Error("OpenAPI / Swagger の定義ではありません（openapi または swagger の項目がない）");
  const global = Array.isArray(root.security) ? root.security : null;
  const servers = Array.isArray(root.servers) ? root.servers.map((s) => String(obj(s).url ?? "")) : [];
  let host: string | null = typeof root.host === "string" ? root.host : null;
  for (const url of servers) {
    try { host = host ?? new URL(url).hostname; } catch { /* relative server URL */ }
  }
  const endpoints: ApiEndpoint[] = [];
  for (const [path, item] of Object.entries(obj(root.paths)).slice(0, 2000)) {
    for (const method of METHODS) {
      const op = obj(obj(item)[method]);
      if (!Object.keys(op).length) continue;
      const sec = Array.isArray(op.security) ? op.security : global;
      const auth = sec === null ? "unknown" : sec.length === 0 || sec.every((r) => !Object.keys(obj(r)).length) ? "none" : "declared";
      const tags = Array.isArray(op.tags) ? op.tags.map(String) : [];
      const role = String(op["x-required-role"] ?? op["x-roles"] ?? "");
      const scopes = (sec ?? []).flatMap((r) => Object.values(obj(r)).flat().map(String));
      const admin = /admin/i.test(role) || tags.some((t) => /admin/i.test(t)) || scopes.some((s) => /admin/i.test(s));
      const ok = obj(obj(op.responses)["200"] ?? obj(op.responses)["201"]);
      const schema = Object.values(obj(ok.content)).map((c) => obj(c).schema)[0] ?? ok.schema;
      endpoints.push(endpoint(method, path, `${fileName}: paths.${path}.${method}`, auth, admin, fields(root, schema)));
    }
  }
  return { title: String(obj(root.info).title ?? fileName), host, endpoints, candidates: endpoints.flatMap(candidates),
    notes: global === null ? ["定義全体の認証（security）が宣言されていないため、各APIの認証は「未確認」として扱います"] : [] };
}

const AUTH_DECORATOR = /@(?:login_required|jwt_required|auth_required|requires_auth|permission_required|token_required)|Depends\(\s*(?:get_current_\w+|auth\w*|verify\w*)/;
const ADMIN_DECORATOR = /@(?:admin_required|staff_member_required|superuser_required|roles?_required\([^)]*admin)/i;

/** Flask / FastAPI (Python) and Express (JavaScript / TypeScript) route definitions. */
export function analyzeRoutes(files: { path: string; text: string }[]): ApiAnalysis {
  const endpoints: ApiEndpoint[] = [];
  // FastAPI dependency aliases: `CurrentUser = Annotated[User, Depends(get_current_user)]`
  const aliases = new Set(files.flatMap(({ text }) => [...text.matchAll(
    /^(\w+)\s*=\s*Annotated\[[^\n]*Depends\(\s*(?:get_current_\w+|auth\w*|verify\w*|require\w*)/gm)].map((m) => m[1])));
  const aliasUse = aliases.size ? new RegExp(`:\\s*(?:${[...aliases].join("|")})\\b`) : null;
  const middlewareFiles: string[] = [];
  for (const { path: file, text } of files) {
    const lines = text.split("\n");
    // an app-wide HTTP middleware that answers 401 declares auth for the routes of this file,
    // except the paths it names (exclusions such as "/health" or a PUBLIC_PATHS set)
    const mw = middleware401(lines, files);
    if (mw) middlewareFiles.push(`${file}: アプリ全体のミドルウェアが 401 を返します。`
      + (mw.optional ? "認証情報が無い要求を通すか、確認するパスを読み取れない書き方のため、このファイルのルートは未確認のままです"
        : "対象と読めるルートを「認証の宣言あり」とし、除外されるパス・対象外のパスは未確認のままにしました")
      + (mw.bypass.length ? `。認証を求めない条件があります（${mw.bypass.join("、")}）。設定や送信元によっては認証が外れます` : ""));
    lines.forEach((line, i) => {
      const py = line.match(/^\s*@\w+\.(route|get|post|put|patch|delete)\(\s*["']([^"']+)["'](.*)$/);
      // a Python decorator line also looks like `app.get("...")`: it is never read as JavaScript
      const js = py ? null : line.match(/\b(?:app|router)\.(get|post|put|patch|delete)\(\s*["'`]([^"'`]+)["'`]/);
      if (!py && !js) return;
      const [verb, route, rest] = py ? [py[1], py[2], py[3]] : [js![1], js![2], line];
      const methods = verb === "route" ? (rest.match(/methods\s*=\s*\[([^\]]*)\]/)?.[1].match(/[A-Za-z]+/g) ?? ["GET"]) : [verb];
      // this handler only: its stacked decorators and its own `def` signature (Python), or the
      // route line itself (JavaScript) - never the neighbouring handler's
      let block = line;
      if (py) {
        let start = i;
        while (start > 0 && /^\s*@/.test(lines[start - 1])) start--;
        let end = i;
        while (end < lines.length - 1 && end - i < 6 && !/^\s*(?:async\s+)?def\b/.test(lines[end])) end++;
        while (end < lines.length - 1 && end - i < 14 && !/\)\s*(?:->[^:]*)?:\s*(?:#.*)?$/.test(lines[end])) end++;
        block = lines.slice(start, end + 1).join("\n");
      }
      const own = AUTH_DECORATOR.test(block) || (aliasUse?.test(block) ?? false)
        || (!!js && /\b(?:auth|authenticate|requireAuth|passport)\w*/.test(line.replace(js[0], "")));
      const covers = py && mw ? middlewareCovers(mw, route) : null;
      const viaMw = covers === "yes";
      const auth = own || viaMw ? "declared" : "unknown";
      const basis = own ? "route" : viaMw ? "middleware" : covers === "no" ? "middleware_excluded"
        : covers === "unknown" ? "middleware_conditional" : undefined;
      const admin = ADMIN_DECORATOR.test(block) || (!!js && /\b(?:admin|requireRole\(\s*["']admin)/i.test(line));
      for (const m of methods) endpoints.push({ ...endpoint(m, route, `${file}:${i + 1}`, auth, admin), ...(basis ? { authBasis: basis } : {}) });
    });
  }
  return { title: "プロジェクトのルート定義", host: null, endpoints, candidates: endpoints.flatMap(candidates),
    notes: ["ソースのルート定義から読み取った候補です。認証の有無はデコレーター・依存関係・アプリ全体のミドルウェアから推定できた場合だけ「宣言あり」とし、それ以外は未確認です",
      "「宣言あり」はコード上の宣言です。実際に認証が強制されているかは、承認後に試験用アカウントで実行して確かめるまで分かりません",
      ...middlewareFiles] };
}

type Middleware = {
  /** paths it lets through without the check: exact values, and prefixes (startswith) */
  exact: string[]; prefix: string[];
  /** when it checks only some paths: those (exact / prefix); empty = every other path */
  onlyExact: string[]; onlyPrefix: string[];
  /** conditions other than the path under which the 401 is never reached */
  bypass: string[];
  /** the check runs only when a credential is present (`if token and not verify(token)`) */
  optional: boolean;
};

/** The body of a FastAPI/Starlette `@app.middleware("http")` that returns 401, read as far as
 * this static reading can: which paths its conditions name (directly or through a constant of
 * this or another file), whether they are let through or are the only ones checked, and the
 * other conditions under which the 401 is not reached. Anything it cannot place stays unknown. */
function middleware401(lines: string[], files: { path: string; text: string }[]): Middleware | null {
  const at = lines.findIndex((l) => /^@\w+\.middleware\(\s*["']http["']\s*\)/.test(l));
  if (at < 0) return null;
  let end = at + 1;
  while (end < lines.length && (end <= at + 1 || !/^\S/.test(lines[end]) || /^\s*#/.test(lines[end]))) end++;
  const bodyLines = lines.slice(at, end);
  const at401 = bodyLines.findIndex((l) => /status_code\s*=\s*401|HTTP_401_UNAUTHORIZED/.test(l));
  if (at401 < 0) return null;
  const sources = [lines, ...files.map((f) => f.text.split("\n"))];
  const literals = (t: string) => [...t.matchAll(/["'](\/[^"'\s]*)["']/g)].map((m) => m[1]);
  // a constant's path literals: `NAME = {...}` here or in another file (`access.OPEN_PATHS`)
  const resolve = (expr: string) => {
    const out = literals(expr);
    for (const ref of expr.match(/[A-Za-z_][\w.]*/g) ?? []) {
      const name = ref.split(".").pop()!;
      if (/^(?:request|url|path|not|in|and|or|startswith|endswith)$/.test(name)) continue;
      for (const src of sources) {
        const def = src.findIndex((l) => new RegExp(`^${name}\\s*(?::[^=]*)?=`).test(l));
        if (def < 0) continue;
        let stop = def;
        while (stop < src.length - 1 && stop - def < 40 && !/[\])}]\s*$/.test(src[stop]) && !/=\s*["'][^"']*["']\s*$/.test(src[stop])) stop++;
        out.push(...literals(src.slice(def, stop + 1).join("\n")));
        break;
      }
    }
    return out;
  };
  const m: Middleware = { exact: [], prefix: [], onlyExact: [], onlyPrefix: [], bypass: [], optional: false };
  const indentOf = (l: string) => l.match(/^\s*/)![0].length;
  const cond = (l: string) => /^\s*(?:if|elif)\s+(.+?):\s*(?:#.*)?$/.exec(l)?.[1];
  // read one condition; `skips` = true when meeting it means the check is skipped
  const read = (c: string, skips: boolean) => {
    for (const raw of c.split(/\s+(?:and|or)\s+/)) {
      let clause = raw.trim();
      const count = (t: string, c: string) => t.split(c).length - 1;
      while (clause.startsWith("(") && count(clause, "(") > count(clause, ")")) clause = clause.slice(1).trim();
      while (clause.endsWith(")") && count(clause, ")") > count(clause, "(")) clause = clause.slice(0, -1).trim();
      const negated = /^not\s+/.test(clause) || /\snot\s+in\s/.test(clause);
      if (/\bpath\b|\burl\b/.test(clause)) {
        const starts = /startswith\s*\(/.test(clause);
        const values = resolve(clause.replace(/^.*?(?:\snot\s+in\s|\sin\s|startswith\s*\()/, ""));
        // "skipped when it matches" = let through; "checked only when it matches" = the only ones checked
        const letThrough = skips !== negated;
        (letThrough ? (starts ? m.prefix : m.exact) : (starts ? m.onlyPrefix : m.onlyExact)).push(...values);
        if (!values.length && !letThrough) m.optional = true;      // only some paths, which we cannot tell
        if (!values.length && letThrough) m.bypass.push(clause.slice(0, 60));
        continue;
      }
      if (!skips && /^[A-Za-z_][\w.]*$/.test(clause)) { m.optional = true; continue; }   // `if token and not verify(token)`
      const call = /^(not\s+)?([A-Za-z_][\w.]*)\s*\(/.exec(clause);
      if (call && !(call[1] && /(?:^|\.)(?:ok|is_?auth\w*|verify\w*|check\w*|valid\w*)$/i.test(call[2])) && !/device_for|cookies|headers\.get|\.get$/.test(call[2]))
        m.bypass.push(`${call[2]}(${/\(\s*\)/.test(clause) ? "" : "…"})`);
      else if (!call && skips) m.bypass.push(clause.slice(0, 60));
    }
  };
  // the `if`s around the 401: meeting them is required for the check
  let indent = indentOf(bodyLines[at401]);
  for (let k = at401 - 1; k > 0; k--) {
    const c = cond(bodyLines[k]);
    if (indentOf(bodyLines[k]) >= indent || !c) { if (indentOf(bodyLines[k]) < indent && !/^\s*(?:else|try|with|for|async)\b/.test(bodyLines[k]) ) indent = indentOf(bodyLines[k]); continue; }
    indent = indentOf(bodyLines[k]);
    read(c, false);
  }
  // an earlier `if ...: return await call_next(request)` skips the check when met
  for (let k = 1; k < at401; k++) {
    const c = cond(bodyLines[k]);
    if (!c) continue;
    const inner = bodyLines.slice(k + 1).findIndex((l) => indentOf(l) <= indentOf(bodyLines[k]) && l.trim());
    const block = bodyLines.slice(k + 1, inner < 0 ? undefined : k + 1 + inner);
    if (k + block.length < at401 && block.some((l) => /call_next\s*\(/.test(l))) read(c, true);
  }
  for (const key of ["exact", "prefix", "onlyExact", "onlyPrefix", "bypass"] as const) m[key] = [...new Set(m[key])];
  return m;
}

/** Whether this middleware checks the route: "yes", "no" (let through or not one it checks), "unknown". */
function middlewareCovers(m: Middleware, route: string): "yes" | "no" | "unknown" {
  if (m.optional) return "unknown";
  if (m.exact.includes(route) || m.prefix.some((x) => x.length > 1 && route.startsWith(x))) return "no";
  if (m.onlyExact.length || m.onlyPrefix.length)
    return m.onlyExact.includes(route) || m.onlyPrefix.some((x) => route.startsWith(x)) ? "yes" : "no";
  return "yes";
}

/** "{org}" etc. still in a path: the user has to put a real test record's value there. */
export const hasTemplate = (path: string) => /\{[^}]*\}/.test(path);
