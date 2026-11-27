"""Fix-support evaluation on sample apps run with real Flask (isolated interpreter).

For each case in tests/fixtures/fix_eval: the original must reproduce its exploit; a fix is
applied to a scratch copy only, then the same exploit and the same normal-function requests
run against the copy. Methods:
  fixed      the deterministic generator (web/src/lib/fixPatch.ts)
  ai         a local model (OpenAI-compatible, loopback) writes root cause, evidence, fixed file
             and a re-test (only with --ai-url; never a paid or remote endpoint)
  fixed+ai   the deterministic fix when there is one, the AI fix otherwise; the explanation is the
             AI's only where its cited line and names exist in the source
Scoring (100): root cause 20, evidence 20, fix 30 (exploit stopped 15, applies and runs 15),
side effects 15 (normal requests unchanged), re-test 10, time 5. The rubric terms are fixed per
vulnerability class below, before any run.

Usage: python3 scripts/eval_fix_support.py --python <flask venv python> [--ai-url URL --ai-model M]
       [--cases a,b] [--out FILE]
"""
from __future__ import annotations

import argparse
import http.client
import json
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CASES = ROOT / "tests/fixtures/fix_eval"
ROOT_CAUSE_TERMS = {   # what a correct root-cause statement has to name (any one per group)
    "path": [["traversal", "..", "outside", "トラバーサル", "外", "../"], ["normaliz", "realpath", "resolve", "base", "正規化", "基準", "ディレクトリ", "directory"]],
    "sql": [["concatenat", "f-string", "string format", "埋め込", "連結", "文字列"], ["parameter", "placeholder", "bind", "プレースホルダ", "パラメータ"]],
    "command": [["shell", "シェル"], ["quote", "escape", "argument list", "引数", "エスケープ", "クォート"]],
    "xss": [["escap", "エスケープ", "encod", "sanitiz"], ["html", "script", "HTML"]],
}
FIXED_EXPLANATION = {   # the fixed rule's own text (projectDefense PYTHON_FLOW title + fix)
    "path": "外部入力からファイルパス。許可したディレクトリ内の固定名だけを解決し、パスの正規化後に範囲を確認する。",
    "sql": "外部入力からSQL実行。値はプレースホルダーとパラメーターで渡し、SQL文字列に連結しない。",
    "command": "外部入力からOSコマンド実行。シェルを使わず引数の配列で実行し、許可した値だけを受け付ける。",
    "xss": "外部入力をそのままHTML応答。応答はテンプレートの自動エスケープを通すか、html.escapeしてから返す。",
}
FIXED_RETEST = "修正後のフォルダを選び直し、同じ検査を再実行して項目が消えることを確認する。"


def _port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class Served:
    def __init__(self, folder: Path, python: str):
        self.port = _port()
        code = (f"import sys, runpy; sys.path[:0] = [{str(folder)!r}]; sys.argv = ['app.py', '{self.port}']; "
                f"runpy.run_path({str(folder / 'app.py')!r}, run_name='__main__')")
        self.proc = subprocess.Popen([python, "-I", "-c", code], cwd=folder,
                                     stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        for _ in range(100):
            if self.proc.poll() is not None:
                raise RuntimeError("app exited")
            try:
                socket.create_connection(("127.0.0.1", self.port), timeout=0.2).close()
                return
            except OSError:
                time.sleep(0.05)
        raise RuntimeError("app did not start")

    def get(self, path: str) -> tuple[int, str]:
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        try:
            conn.request("GET", path)
            r = conn.getresponse()
            return r.status, r.read().decode("utf-8", "replace")
        finally:
            conn.close()

    def close(self):
        self.proc.terminate()
        self.proc.wait(timeout=5)


def measure(folder: Path, spec: dict, python: str) -> dict:
    try:
        app = Served(folder, python)
    except RuntimeError as e:
        return {"runs": False, "error": str(e)}
    try:
        normal = [(lambda st, body: st == want and text in body)(*app.get(path)) for path, want, text in spec["normal"]]
        exploit = [marker in app.get(path)[1] for path, marker in spec["exploit"]]
    finally:
        app.close()
    return {"runs": True, "normal_ok": all(normal), "exploited": any(exploit)}


def fixed_fix(app: Path) -> dict:
    out = subprocess.run(["node", str(ROOT / "scripts/fix_patch_cli.mjs"), str(app), "app.py"],
                         capture_output=True, text=True, timeout=60, check=True)
    fixes = json.loads(out.stdout)
    ok = [f for f in fixes if f["ok"]]
    return {"patched": ok[0]["patched"] if ok else None, "findings": [f["finding"] for f in fixes],
            "diff_lines": ok[0]["changedLines"] if ok else None}


AI_SCHEMA = {"type": "object", "additionalProperties": False,
             "required": ["root_cause", "evidence_line", "evidence_names", "fixed_file", "side_effects", "retest"],
             "properties": {"root_cause": {"type": "string"}, "evidence_line": {"type": "integer"},
                            "evidence_names": {"type": "array", "maxItems": 5, "items": {"type": "string"}},
                            "fixed_file": {"type": "string"}, "side_effects": {"type": "string"},
                            "retest": {"type": "string"}}}


def ai_fix(source: str, finding: dict, url: str, model: str) -> dict:
    if not re.match(r"^http://(127\.0\.0\.1|localhost)(:\d+)?/", url):
        raise SystemExit("--ai-url must be a loopback http URL")
    prompt = ("The static check reports this finding in app.py: "
              f"{finding['kind']} at line {finding['line']} in function {finding['func']} (sink {finding['sink']}).\n"
              "Explain the root cause, cite the line and the variable/function names it rests on, return the whole "
              "corrected app.py with the smallest change that keeps normal behaviour, say what the change could "
              "affect, and say how to re-test it (which request, what result). Answer in JSON only.\n\n"
              "app.py (line numbers added):\n" + "\n".join(f"{i + 1:3}| {l}" for i, l in enumerate(source.split("\n"))))
    body = {"model": model, "temperature": 0, "reasoning_effort": "none",
            "messages": [{"role": "system", "content": "You are a security engineer fixing a reported defect."},
                         {"role": "user", "content": prompt}],
            "response_format": {"type": "json_schema", "json_schema": {"name": "fix", "strict": True, "schema": AI_SCHEMA}}}
    t = time.monotonic()
    req = urllib.request.Request(url, data=json.dumps(body).encode(), headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=300) as r:
        data = json.load(r)
    answer = json.loads(data["choices"][0]["message"]["content"])
    answer["seconds"] = round(time.monotonic() - t, 1)
    answer["tokens"] = (data.get("usage") or {}).get("total_tokens")
    return answer


def has_terms(text: str, kind: str) -> bool:
    low = text.lower()
    return all(any(t.lower() in low for t in group) for group in ROOT_CAUSE_TERMS[kind])


def score(kind: str, explanation: str, evidence_ok: bool, result: dict | None, retest: str, route: str,
          seconds: float) -> dict:
    s = {"root_cause": 20 if has_terms(explanation, kind) else 0,
         "evidence": 20 if evidence_ok else 0,
         "fix_applies": 15 if result and result.get("runs") else 0,
         "fix_stops_exploit": 15 if result and result.get("runs") and not result.get("exploited") else 0,
         "side_effects": 15 if result and result.get("runs") and result.get("normal_ok") else 0,
         "retest": (10 if route in retest and re.search(r"(?i)expect|should|確認|返|returns?|blocked|拒否|含ま", retest)
                    else 5 if retest else 0),
         "time": 5 if seconds <= 10 else 3 if seconds <= 60 else 0}
    s["total"] = sum(s.values())
    return s


def run_case(name: str, python: str, ai_url: str | None, ai_model: str) -> dict:
    folder = CASES / name
    spec = json.loads((folder / "case.json").read_text())
    source = (folder / "app.py").read_text()
    route = spec["normal"][0][0].split("?")[0]
    base = measure(folder, spec, python)
    row = {"case": name, "kind": spec["kind"], "split": spec["split"], "baseline": base}
    if not (base.get("runs") and base.get("normal_ok") and base.get("exploited")):
        row["invalid_case"] = True
        return row
    t = time.monotonic()
    fx = fixed_fix(folder / "app.py")
    fixed_s = time.monotonic() - t
    finding = next((f for f in fx["findings"] if f["kind"] == spec["kind"]), None)
    row["fixed_found"] = finding is not None

    def apply(patched: str | None) -> dict | None:
        if not patched:
            return None
        with tempfile.TemporaryDirectory() as tmp:
            copy = Path(tmp) / "work"
            shutil.copytree(folder, copy)
            (copy / "app.py").write_text(patched)
            return measure(copy, spec, python)
    fixed_result = apply(fx["patched"])
    row["fixed"] = {"result": fixed_result, "diff_lines": fx["diff_lines"],
                    "score": score(spec["kind"], FIXED_EXPLANATION[spec["kind"]], finding is not None,
                                   fixed_result, FIXED_RETEST, route, fixed_s)}
    if ai_url and finding:
        try:
            ans = ai_fix(source, finding, ai_url, ai_model)
        except Exception as e:  # noqa: BLE001
            row["ai"] = {"error": type(e).__name__}
            return row
        names_ok = all(n and n in source for n in ans["evidence_names"]) and bool(ans["evidence_names"])
        evidence_ok = ans["evidence_line"] == finding["line"] and names_ok
        ai_result = apply(ans["fixed_file"])
        row["ai"] = {"result": ai_result, "evidence_line": ans["evidence_line"], "evidence_names": ans["evidence_names"],
                     "seconds": ans["seconds"], "tokens": ans["tokens"], "root_cause": ans["root_cause"][:400],
                     "retest": ans["retest"][:300], "side_effects": ans["side_effects"][:300],
                     "score": score(spec["kind"], ans["root_cause"], evidence_ok, ai_result, ans["retest"], route,
                                    ans["seconds"])}
        # fixed + AI: the deterministic fix if any; the AI's words only where its evidence checks out
        use_fix = fixed_result if fx["patched"] else ai_result
        explanation = ans["root_cause"] if evidence_ok else FIXED_EXPLANATION[spec["kind"]]
        retest = ans["retest"] if evidence_ok else FIXED_RETEST
        row["fixed_ai"] = {"fix_source": "fixed" if fx["patched"] else "ai", "explanation_source": "ai" if evidence_ok else "fixed",
                           "score": score(spec["kind"], explanation, True, use_fix, retest, route,
                                          fixed_s + ans["seconds"])}
    return row


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--python", required=True)
    ap.add_argument("--ai-url")
    ap.add_argument("--ai-model", default="qwen3:8b")
    ap.add_argument("--cases", default="")
    ap.add_argument("--out")
    a = ap.parse_args()
    names = [c for c in a.cases.split(",") if c] or sorted(p.name for p in CASES.iterdir() if (p / "case.json").exists())
    rows = [run_case(n, a.python, a.ai_url, a.ai_model) for n in names]
    summary = {}
    for method in ("fixed", "ai", "fixed_ai"):
        for split in ("dev", "holdout"):
            rs = [r[method]["score"] for r in rows if r.get("split") == split and method in r and "score" in r[method]]
            if rs:
                keys = rs[0].keys()
                summary[f"{method}/{split}"] = {k: round(sum(x[k] for x in rs) / len(rs), 1) for k in keys} | {"n": len(rs)}
    out = {"cases": rows, "summary": summary}
    text = json.dumps(out, ensure_ascii=False, indent=1)
    if a.out:
        Path(a.out).write_text(text + "\n")
    print(json.dumps(summary, ensure_ascii=False, indent=1))
    return 0


if __name__ == "__main__":
    sys.exit(main())
