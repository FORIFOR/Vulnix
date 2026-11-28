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
    out.push({ kind: "auth", endpoint: e, reason: "認証の有無を定義から読み取れない", unknown: ["実装上の認証の有無"] });
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
    // an app-wide HTTP middleware that answers 401: every route of this app is behind it
    const mw = text.match(/@app\.middleware\(\s*["']http["']\s*\)[\s\S]{0,800}?status_code\s*=\s*401/);
    if (mw) middlewareFiles.push(file);
    lines.forEach((line, i) => {
      const py = line.match(/^\s*@\w+\.(route|get|post|put|patch|delete)\(\s*["']([^"']+)["'](.*)$/);
      const js = line.match(/\b(?:app|router)\.(get|post|put|patch|delete)\(\s*["'`]([^"'`]+)["'`]/);
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
      const auth = AUTH_DECORATOR.test(block) || (aliasUse?.test(block) ?? false) || (py && mw)
        || (js && /\b(?:auth|authenticate|requireAuth|passport)\w*/.test(line)) ? "declared" : "unknown";
      const admin = ADMIN_DECORATOR.test(block) || (!!js && /\b(?:admin|requireRole\(\s*["']admin)/i.test(line));
      for (const m of methods) endpoints.push(endpoint(m, route, `${file}:${i + 1}`, auth, admin));
    });
  }
  return { title: "プロジェクトのルート定義", host: null, endpoints, candidates: endpoints.flatMap(candidates),
    notes: ["ソースのルート定義から読み取った候補です。認証の有無はデコレーター・依存関係・アプリ全体のミドルウェアから推定できた場合だけ「宣言あり」とし、それ以外は未確認です",
      ...middlewareFiles.map((f) => `${f}: アプリ全体のミドルウェアが 401 を返すため、このファイルのルートは「認証の宣言あり」としました（除外パスと実装は未確認）`)] };
}

/** "{org}" etc. still in a path: the user has to put a real test record's value there. */
export const hasTemplate = (path: string) => /\{[^}]*\}/.test(path);
