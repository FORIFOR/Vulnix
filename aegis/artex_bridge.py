"""Bridge from the real ARTEX planner to Vulnix's Gateway.

ARTEX (AGPL-3.0, github.com/Autumn-27/artex) plans by calling its `add_intent`
tool: free-text exploration directions, optionally tagged with asset ids. This
module runs ARTEX's planner through a planner-only overlay binary
(integrations/artex/overlay: no Bash/Read/Write/Edit, no WebFetch/WebSearch, no
scope-expansion or finding tools, no workers) and turns its intents into Vulnix
proposals.

Nothing ARTEX says is trusted:
- the overlay's output is validated strictly; a run that reports any tool outside
  the planner allowlist is rejected as a whole;
- an intent never supplies the target, tool, action or arguments. The target comes
  from Vulnix's own registered targets (by the asset id Vulnix handed out), and the
  operation and its arguments come from Vulnix's fixed check catalog. An intent
  only *selects* a catalog entry by what it is about;
- an intent that does not select exactly one catalog entry, names an unregistered
  target, or asks for something outside the catalog (command execution, upload,
  brute force, ...) is kept as an advisory: shown, never executable.

Every reconstructed proposal still goes through ProposalRouter (sanitizing) and
the Gateway (scope, egress, token, emergency stop); L2 items additionally need an
approver and run in the isolated worker.
"""
from __future__ import annotations

import contextlib
import hashlib
import json
import os
import re
import shlex
import shutil
import signal
import subprocess
import sys
import tempfile
import time
import urllib.parse
from dataclasses import dataclass, field

from .confinement import dropped_packets
from pathlib import Path

# The tools the overlay may give the ARTEX planner (exact ARTEX tool names). A run
# whose overlay reports any other tool as available or as allowed is rejected.
PLANNER_TOOL_ALLOWLIST = frozenset({
    "graph_overview", "list_findings", "list_facts", "node_detail",
    "list_goals", "add_intent", "prove_goal", "goal_met",
})

# Names that must never be available to the planner (documented; checked in tests).
FORBIDDEN_TOOLS = frozenset({
    "Bash", "Read", "Write", "Edit", "MultiEdit", "LS", "Glob", "Grep", "WebFetch", "WebSearch",
    "add_company_scope", "add_task_scope", "add_finding", "report_finding", "list_assets",
    "list_untested_assets", "kill_work", "steer_work",
})

ARTEX_MODULE = "github.com/Autumn-27/artex"
OVERLAY_MAIN = f"{ARTEX_MODULE}/cmd/vulnix-planner"

MAX_OUTPUT_BYTES = 1 << 20
# cgroup limits for the ARTEX process: no fork bomb or runaway memory can starve the host
ARTEX_LIMITS = {"pids.max": 512, "memory.max": 2 << 30}
MAX_INTENTS = 50
MAX_SUMMARY = 2000

# Asked for something no catalog entry does: never mapped, whatever else it says.
_OUT_OF_CATALOG = re.compile(
    r"(rce|remote code|command exec|命令执行|コマンド実行|任意.?コード|getshell|webshell|reverse shell|反弹|"
    r"upload|上传|アップロード|brute|爆破|総当たり|password spray|撞库|\bdos\b|denial of service|"
    r"delete|删除|削除|drop table|truncate|写入|書き込み|exfil|外传|持出|lateral|横向|提权|privilege escalation|"
    r"権限昇格|subdomain enum|子域名|port scan|端口扫描|ポートスキャン|nmap|masscan)",
    re.IGNORECASE)


@dataclass(frozen=True)
class CatalogEntry:
    id: str
    tool: str
    action: str
    level: str
    label: str
    keywords: tuple[str, ...]
    check: str | None = None
    finding_id: str | None = None

    def args_for(self, url: str) -> dict:
        if self.tool == "http_probe":
            return {"url": url, "method": "GET"}
        return {"url": url, "check": self.check}


# Vulnix's allowed verification catalog. The ONLY operations an ARTEX intent can lead to.
CATALOG: tuple[CatalogEntry, ...] = (
    CatalogEntry("l2_sqli", "reproduction_probe", "safe_reproduction", "L2",
                 "SQLインジェクション境界の非破壊再現（隔離Worker）",
                 ("sql injection", "sqli", "sql注入", "sqlインジェクション", "sql 注入", "注入点"),
                 check="sqli", finding_id="f_sqli"),
    CatalogEntry("l2_idor", "reproduction_probe", "safe_reproduction", "L2",
                 "認可境界（IDOR）の非破壊再現（検証用アカウント・隔離Worker）",
                 ("idor", "bola", "越权", "水平越权", "access control", "authorization", "アクセス制御", "認可"),
                 check="idor", finding_id="f_idor"),
    CatalogEntry("l2_cve_2021_41773", "reproduction_probe", "safe_reproduction", "L2",
                 "CVE-2021-41773 成立の非破壊再現（隔離Worker）",
                 ("cve-2021-41773", "41773", "path traversal", "路径穿越", "目录穿越", "パストラバーサル"),
                 check="cve_2021_41773", finding_id="f_banner"),
    CatalogEntry("l1_http_probe", "http_probe", "read_only_probe", "L1",
                 "公開設定・応答ヘッダーの非破壊GET（1回）",
                 ("header", "headers", "响应头", "ヘッダー", "banner", "バナー", "fingerprint", "指纹", "フィンガープリント",
                  "server version", "服务器版本", "信息收集", "recon", "偵察", "公開設定", "security header")),
)
CATALOG_BY_ID = {c.id: c for c in CATALOG}


class ArtexBridgeError(RuntimeError):
    """The ARTEX run could not be used (not started, failed, or its output was refused)."""


@dataclass
class ArtexRun:
    """A validated ARTEX planner run. `provenance` says what actually ran."""
    intents: list[dict]
    goal_met: bool
    allowed_tools: list[str]
    tool_calls: list[dict]
    denied_tool_calls: list[str]
    provenance: dict
    elapsed_ms: float


@dataclass
class PlanItem:
    id: str
    intent_id: int
    intent_summary: str
    catalog_id: str
    level: str
    label: str
    target_id: str
    proposal: dict           # reconstructed from Vulnix's registry + catalog only
    status: str = "planned"


@dataclass
class Advisory:
    intent_id: int
    intent_summary: str
    reason: str


@dataclass
class Reconstruction:
    items: list[PlanItem] = field(default_factory=list)
    advisories: list[Advisory] = field(default_factory=list)


# ---------------------------------------------------------------------------
# provenance: is this really an ARTEX build?
# ---------------------------------------------------------------------------
# Go module info embedded in every module-aware Go binary ("go version -m" prints it):
#   path\t<main package>\n  mod\t<main module>\t<version>...\n  dep\t<module>\t<version>...
_MODINFO_PATH = re.compile(rb"path\t" + re.escape(OVERLAY_MAIN.encode()) + rb"\n")
_MODINFO_MOD = re.compile(rb"\nmod\t" + re.escape(ARTEX_MODULE.encode()) + rb"\t")
_MODINFO_NORMA = re.compile(rb"\ndep\tgithub\.com/Autumn-27/norma\t(v[0-9][^\t\n]{0,40})")


def inspect_bytes(data: bytes, path: str = "", expected_sha256: str = "") -> dict:
    """What an executable is. `kind` is "artex-binary" only for a native executable
    whose embedded Go module info names the ARTEX overlay main package in the ARTEX
    module; anything else (a script, a stand-in) is "unverified" and is never shown
    as ARTEX. `pinned` is True only when its SHA-256 equals the operator's pin."""
    native = data[:4] in (b"\x7fELF", b"\xcf\xfa\xed\xfe", b"\xce\xfa\xed\xfe", b"\xca\xfe\xba\xbe")
    go_info = b"\xff Go buildinf:" in data
    main_path = bool(_MODINFO_PATH.search(data))
    main_mod = bool(_MODINFO_MOD.search(data))
    norma = _MODINFO_NORMA.search(data)
    sha = hashlib.sha256(data).hexdigest()
    kind = "artex-binary" if (native and go_info and main_path and main_mod) else "unverified"
    return {
        "kind": kind,
        "path": str(path),
        "sha256": sha,
        "size": len(data),
        "native": native,
        "go_buildinfo": go_info,
        "artex_overlay_main": main_path and main_mod,
        "norma_version": norma.group(1).decode(errors="replace") if norma else None,
        "pinned": bool(expected_sha256) and kind == "artex-binary" and sha == expected_sha256.strip().lower(),
    }


def inspect_executable(path: str | os.PathLike, expected_sha256: str = "") -> dict:
    p = Path(path)
    try:
        data = p.read_bytes()
    except OSError as e:
        return {"kind": "missing", "path": str(p), "error": type(e).__name__, "pinned": False}
    return inspect_bytes(data, str(p), expected_sha256)


# ---------------------------------------------------------------------------
# running the planner
# ---------------------------------------------------------------------------
def require_loopback_llm(url: str) -> str:
    """The ARTEX planner is verified against a local mock LLM only."""
    u = urllib.parse.urlsplit(str(url or ""))
    if u.scheme not in ("http", "https") or (u.hostname or "") not in ("127.0.0.1", "::1", "localhost"):
        raise ArtexBridgeError("ARTEX の LLM はローカル（ループバック）のモデルのみ使用できます")
    return url


def require_loopback_dsn(dsn: str) -> str:
    """ARTEX's store (PostgreSQL) must be a local database. Query parameters that
    can redirect the connection (host, hostaddr, service) are refused."""
    u = urllib.parse.urlsplit(str(dsn or ""))
    if "," in u.netloc:          # multi-host DSN: only the first host would be checked
        raise ArtexBridgeError("ARTEX のデータベースに複数の接続先は指定できません")
    try:
        _ = u.port
    except ValueError:
        raise ArtexBridgeError("ARTEX のデータベースの接続先が不正です") from None
    if u.scheme not in ("postgres", "postgresql") or (u.hostname or "") not in ("127.0.0.1", "::1", "localhost"):
        raise ArtexBridgeError("ARTEX のデータベースはローカル（ループバック）の PostgreSQL のみ使用できます")
    q = urllib.parse.parse_qs(u.query)
    if any(k in q for k in ("host", "hostaddr", "service", "servicefile")):
        raise ArtexBridgeError("ARTEX のデータベース接続先を変更するパラメータは使用できません")
    return dsn


def planner_hidden_paths(forbidden_paths=()) -> list[str]:
    """What the ARTEX planner must not see at all (covered by empty tmpfs in its mount
    view): users' homes, shared temp directories, the Vulnix installation, and the
    directories holding Vulnix's protected files (the data directory)."""
    repo = str(Path(__file__).resolve().parents[1])
    dirs = {str(Path(f).resolve().parent) for f in forbidden_paths}
    return sorted({"/home", "/root", "/tmp", "/var/tmp", "/dev/shm", repo, *dirs})


def _endpoint(url: str, default_port: int) -> tuple[str, int]:
    """(ip, port) of a loopback URL/DSN for pinning in the kernel ruleset. Confined runs
    need an IP literal: a name would need resolving inside the confinement."""
    u = urllib.parse.urlsplit(url)
    host = u.hostname or ""
    if host == "localhost":
        raise ArtexBridgeError("隔離して実行する場合、LLM・DB の接続先は 127.0.0.1 などの IP で指定してください")
    return host, int(u.port or default_port)


def run_artex_planner(command: list[str], request: dict, *, llm_url: str, llm_model: str = "mock",
                      llm_key: str = "", pg_dsn: str = "", timeout_s: float = 120.0,
                      expected_sha256: str = "", confinement=None, forbidden_paths=(),
                      on_leftover=None, on_started=None, on_finished=None, may_start=None) -> ArtexRun:
    """`confinement`: a Vulnix confinement provider (aegis.confinement.KernelConfinement).
    When given, ARTEX runs inside a per-run cgroup v2 + nftables confinement under its
    own unprivileged uid, with no capabilities, no_new_privs and the seccomp launcher;
    it can open TCP connections ONLY to the LLM and database endpoints, and cannot
    read `forbidden_paths` (verified by the kernel probe before ARTEX starts)."""
    if not command:
        raise ArtexBridgeError("ARTEX プランナーが設定されていません")
    require_loopback_llm(llm_url)
    if pg_dsn:
        require_loopback_dsn(pg_dsn)
    exe = command[0]
    try:
        exe_bytes = Path(exe).read_bytes()
    except OSError as e:
        raise ArtexBridgeError(f"ARTEX を読み込めません: {type(e).__name__}") from None
    provenance = inspect_bytes(exe_bytes, exe, expected_sha256)
    if expected_sha256 and not provenance["pinned"]:
        raise ArtexBridgeError("ARTEX のバイナリが固定済みのハッシュ（VULNIX_ARTEX_EXPECTED_SHA256）と一致しません")
    started = time.monotonic()
    isolation: dict = {"confined": False}
    sess = None
    with contextlib.ExitStack() as stack:
        # ignore_errors: a directory the confined uid still owns must not mask the real
        # outcome (the session removes it; if it cannot, that is reported below)
        work = tempfile.mkdtemp(prefix="vulnix-artex-")
        stack.callback(shutil.rmtree, work, True)
        home = Path(work) / "home"
        home.mkdir(mode=0o700)
        if confinement is not None:
            os.chmod(work, 0o755)            # the confined uid must reach the binary
            llm_ep = _endpoint(llm_url, 443 if llm_url.startswith("https") else 80)
            extra = (_endpoint(pg_dsn, 5432),) if pg_dsn else ()
            try:
                created = confinement.session(
                    llm_ep[0], llm_ep[1], forbidden_paths=tuple(forbidden_paths),
                    protected_pid=os.getpid(), extra_endpoints=extra, limits=ARTEX_LIMITS,
                    namespaces={"hide": planner_hidden_paths(forbidden_paths), "keep": [work]})
                # on record BEFORE anything runs in it (the probe included): a probe that
                # cannot be killed is recorded, and an emergency stop during set-up sees it
                if on_leftover is not None:
                    try:
                        created.on_leftover = on_leftover
                    except AttributeError:
                        pass
                if on_started is not None:
                    on_started(created)          # raises when a stop already happened
                if on_finished is not None:
                    stack.callback(on_finished, created)
                sess = stack.enter_context(created)
                own = getattr(sess, "own_directory", None)
                if own is not None:
                    own(home)                    # the run's own writable directory
            except ArtexBridgeError:
                raise
            except Exception as e:  # noqa: BLE001 - any confinement failure: nothing starts
                raise ArtexBridgeError(f"ARTEX を隔離して起動できません: {str(e)[:200]}") from None
            isolation = {"confined": True, **dict(getattr(sess, "evidence", {}) or {}),
                         "limits": dict(ARTEX_LIMITS)}
        if provenance["kind"] == "artex-binary":
            # run exactly the bytes that were inspected (and hashed): a swap of the file
            # on disk between inspection and execution changes nothing
            copy = Path(work) / "artex-vulnix-planner"
            copy.write_bytes(exe_bytes)
            copy.chmod(0o755 if sess is not None else 0o700)
            command = [str(copy), *command[1:]]
        # A clean environment: no inherited keys, tokens or proxies reach ARTEX.
        env = {"PATH": "/usr/bin:/bin", "HOME": str(home), "TMPDIR": str(home), "LANG": "C.UTF-8",
               "ARTEX_LLM_BASE_URL": llm_url, "ARTEX_LLM_MODEL": llm_model,
               "ARTEX_LLM_API_KEY": llm_key or "local-mock-no-key"}
        if pg_dsn:
            env["ARTEX_PG_DSN"] = pg_dsn
        argv = command
        listing = getattr(sess, "_listing", None)
        drops_before = 0
        if sess is not None:
            try:
                if hasattr(sess, "still_enforced") and not sess.still_enforced():
                    raise ArtexBridgeError("ARTEX の隔離が起動前に確認できなくなりました")
                argv = sess.wrap(list(command), env_keys=tuple(k for k in env if k != "PATH"),
                                 cpu_seconds=int(timeout_s) + 5, interpreter=sys.executable)
                if listing is not None:
                    drops_before = dropped_packets(listing())
            except ArtexBridgeError:
                raise
            except Exception as e:  # noqa: BLE001 - nothing has started
                raise ArtexBridgeError(f"ARTEX を隔離して起動できません: {str(e)[:200]}") from None
        def stopped() -> bool:
            return bool(getattr(sess, "_cancelled", False)) or (may_start is not None and not may_start())
        if sess is not None and stopped():
            raise ArtexBridgeError("緊急停止されたため ARTEX を起動しません")
        try:
            proc = subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                    stderr=subprocess.PIPE, cwd=work, env=env,
                                    start_new_session=True, close_fds=True)
        except OSError as e:
            raise ArtexBridgeError(f"ARTEX を起動できません: {type(e).__name__}") from None
        if sess is not None and stopped():
            # a stop landed between the check and the start: it dies right away
            sess.kill()
        try:
            out, err = proc.communicate(json.dumps(request, ensure_ascii=False).encode(), timeout=timeout_s)
        except subprocess.TimeoutExpired:
            if sess is not None:
                sess.kill()                      # it runs as another uid: kill the cgroup
            try:
                os.killpg(proc.pid, signal.SIGKILL)
            except (ProcessLookupError, PermissionError):
                pass
            try:
                proc.communicate(timeout=15)
            except subprocess.TimeoutExpired:
                raise ArtexBridgeError("ARTEX プランナーの停止を確認できません（隔離は維持されています）") from None
            raise ArtexBridgeError("ARTEX プランナーが制限時間内に終了しませんでした") from None
        if sess is not None:
            enforced = bool(sess.still_enforced()) if hasattr(sess, "still_enforced") else True
            isolation["enforced_after_run"] = enforced
            if listing is not None:
                # packets of THIS run (ARTEX's own) that the kernel dropped: independent
                # of anything ARTEX reports about itself
                isolation["run_dropped_packets"] = dropped_packets(listing()) - drops_before
            if not enforced:
                raise ArtexBridgeError("ARTEX の実行中に隔離が確認できなくなったため、結果を使用しません")
    elapsed = round((time.monotonic() - started) * 1000, 1)
    if sess is not None and getattr(sess, "leftover", False):
        # something of the run could not be removed: it stays confined, and we say so
        raise ArtexBridgeError("ARTEX の隔離を解除できない残存プロセスがあります（隔離は維持されています）")
    if sess is not None:
        isolation["files_left"] = bool(getattr(sess, "files_left", False))
    if len(out) > MAX_OUTPUT_BYTES:
        raise ArtexBridgeError("ARTEX の出力が大きすぎます")
    try:
        data = json.loads(out.decode("utf-8", "replace").strip() or "null")
    except ValueError:
        raise ArtexBridgeError("ARTEX の出力が JSON ではありません") from None
    if proc.returncode != 0:
        msg = data.get("error") if isinstance(data, dict) else None
        raise ArtexBridgeError(f"ARTEX プランナーが失敗しました（exit {proc.returncode}）: {str(msg or '')[:200]}")
    run = parse_planner_output(data, provenance, elapsed)
    run.provenance["stderr_tail_sha256"] = hashlib.sha256(err[-4096:]).hexdigest()
    run.provenance["isolation"] = isolation
    if run.provenance.get("egress_canary"):
        # what ARTEX reports about its own canary connection: shown as self-reported;
        # the kernel's own count is run_dropped_packets
        run.provenance["egress_canary"] = "self-reported: " + run.provenance["egress_canary"]
    return run


def parse_planner_output(data: object, provenance: dict, elapsed_ms: float = 0.0) -> ArtexRun:
    if not isinstance(data, dict) or data.get("engine") != "artex":
        raise ArtexBridgeError("ARTEX の出力形式ではありません")
    if data.get("error"):
        raise ArtexBridgeError(f"ARTEX エラー: {str(data['error'])[:200]}")
    allowed = data.get("allowed_tools")
    if not isinstance(allowed, list) or not all(isinstance(t, str) for t in allowed):
        raise ArtexBridgeError("ARTEX の出力に allowed_tools がありません")
    extra = sorted(set(allowed) - PLANNER_TOOL_ALLOWLIST)
    if extra:
        raise ArtexBridgeError(f"許可外のツールが ARTEX に与えられていました: {', '.join(extra)[:200]}")
    calls = data.get("tool_calls") or []
    if not isinstance(calls, list):
        raise ArtexBridgeError("tool_calls が不正です")
    clean_calls = []
    for c in calls[:500]:
        if not isinstance(c, dict):
            continue
        name = str(c.get("name", ""))[:80]
        ok = bool(c.get("allowed"))
        if ok and name not in PLANNER_TOOL_ALLOWLIST:
            raise ArtexBridgeError(f"許可外のツール {name} が実行されたと報告されました")
        clean_calls.append({"name": name, "allowed": ok})
    denied = [str(x)[:80] for x in (data.get("denied_tool_calls") or []) if isinstance(x, (str, int))][:500]
    intents_raw = data.get("intents") or []
    if not isinstance(intents_raw, list):
        raise ArtexBridgeError("intents が不正です")
    intents = []
    for it in intents_raw[:MAX_INTENTS]:
        if not isinstance(it, dict):
            continue
        summary = it.get("summary")
        if not isinstance(summary, str) or not summary.strip():
            continue
        ids = it.get("asset_ids") or []
        # an ARTEX build always reports the field; if it is missing, fail closed
        if "unmapped_asset_ids" in it:
            unmapped = it.get("unmapped_asset_ids")
        else:
            unmapped = [] if provenance.get("kind") != "artex-binary" else ["missing"]
        intents.append({
            "id": int(it["id"]) if isinstance(it.get("id"), int) else 0,
            "summary": summary.strip()[:MAX_SUMMARY],
            "asset_ids": [i for i in ids if isinstance(i, int) and not isinstance(i, bool)][:20]
            if isinstance(ids, list) else [],
            "priority": it["priority"] if isinstance(it.get("priority"), int) else 5,
            "unmapped": bool(unmapped) if isinstance(unmapped, list) else unmapped is not None,
        })
    prov = dict(provenance)
    prov.update({
        "engine": "artex",
        "artex_module": str(data.get("artex_module", ""))[:120],
        "artex_commit": str(data.get("artex_commit", ""))[:64],
        "go_version": str(data.get("go_version", ""))[:40],
        "egress_canary": str(data.get("egress_canary", ""))[:200],
    })
    return ArtexRun(intents=intents, goal_met=bool(data.get("goal_met")), allowed_tools=list(allowed),
                    tool_calls=clean_calls, denied_tool_calls=denied, provenance=prov,
                    elapsed_ms=elapsed_ms)


# ---------------------------------------------------------------------------
# reconstruction: intents -> Vulnix catalog proposals
# ---------------------------------------------------------------------------
def classify(summary: str) -> tuple[CatalogEntry | None, str]:
    """Which catalog entry an intent is about - or why none."""
    text = summary.lower()
    if _OUT_OF_CATALOG.search(text):
        return None, "許可済みの検証カタログ外の操作を含むため実行しません"
    l2 = [c for c in CATALOG if c.level == "L2" and any(k in text for k in c.keywords)]
    if len(l2) > 1:
        return None, "複数の検証項目に該当し一意に決められないため実行しません"
    if l2:
        return l2[0], ""
    l1 = [c for c in CATALOG if c.level == "L1" and any(k in text for k in c.keywords)]
    if l1:
        return l1[0], ""
    return None, "許可済みの検証カタログに該当しないため実行しません"


def reconstruct(intents: list[dict], targets: list[dict], run_id: str) -> Reconstruction:
    """`targets`: Vulnix's registered, in-scope targets as handed to ARTEX
    ({asset_id, target_id, url}). Only these can ever be a target."""
    by_asset = {t["asset_id"]: t for t in targets}
    out = Reconstruction()
    seen: set[tuple[str, str]] = set()
    for it in intents:
        summary, iid = it["summary"], it["id"]
        entry, why = classify(summary)
        if entry is None:
            out.advisories.append(Advisory(iid, summary, why))
            continue
        if it.get("unmapped"):
            out.advisories.append(Advisory(iid, summary, "登録されていない対象を含むため実行しません"))
            continue
        asset_ids = it.get("asset_ids") or []
        if not asset_ids:
            if len(targets) != 1:
                out.advisories.append(Advisory(iid, summary, "対象が特定されていないため実行しません"))
                continue
            chosen = [targets[0]]
        else:
            unknown = [a for a in asset_ids if a not in by_asset]
            if unknown:
                out.advisories.append(Advisory(iid, summary, "登録されていない対象を含むため実行しません"))
                continue
            chosen = [by_asset[a] for a in asset_ids]
        for tgt in chosen:
            key = (entry.id, tgt["target_id"])
            if key in seen:
                continue
            seen.add(key)
            proposal = {
                "tool": entry.tool, "target_id": tgt["target_id"], "action": entry.action,
                "args": entry.args_for(tgt["url"]),
                "rationale": f"ARTEX intent #{iid}: {summary[:300]}",
            }
            out.items.append(PlanItem(
                id=f"{run_id}_{len(out.items) + 1}", intent_id=iid, intent_summary=summary[:MAX_SUMMARY],
                catalog_id=entry.id, level=entry.level, label=entry.label, target_id=tgt["target_id"],
                proposal=proposal, status="awaiting_approval" if entry.level == "L2" else "planned"))
    return out


def command_from_env() -> list[str]:
    raw = os.environ.get("VULNIX_ARTEX_REAL_CMD", "").strip()
    return shlex.split(raw) if raw else []
