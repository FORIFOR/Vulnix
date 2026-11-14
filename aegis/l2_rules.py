"""Declarative L2 authorization-check rules (`aegis/l2_rules.py`).

The engine in this module is service-agnostic. Everything that is specific to
one target API (hosts, paths, markers, status codes, response fields, finding
texts, which test account plays which role) lives in a profile JSON file under
`aegis/l2_profiles/` (or an extra directory named by `VULNIX_L2_PROFILE_DIR`).

A check never concludes "not reproduced" from an HTTP status alone. Every rule
must declare:

  * `preconditions` - positive controls that have to succeed in the same run
    (e.g. owner B reads the mock resource, account A is authenticated). Each one
    states the expected status AND expected response content.
  * `denied`        - what an enforced boundary looks like for the subject
    request: status codes plus content conditions.
  * `exposed`       - what a broken boundary looks like (status + owner content).

If any precondition is missing or fails, or the subject response matches
neither `denied` nor `exposed`, the result is "unverified".

Every check also carries `spec_status`. Only a check marked "confirmed" - with
`spec_evidence` naming where in the target's own API definition the paths,
statuses and response fields were read - can be executed. A "placeholder" check
is listed as an unmeasured candidate and is refused by the control plane and by
the Gateway tool schema, so guessed values can never produce a verdict.

Loading a profile grants nothing: execution still needs a verified asset,
confirmed scope, stored test accounts, and a per-item human approval.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
from pathlib import Path

BUILTIN_PROFILE_DIR = Path(__file__).parent / "l2_profiles"
PROFILE_DIR_ENV = "VULNIX_L2_PROFILE_DIR"

SEVERITIES = ("critical", "high", "medium", "low", "info")
SPEC_STATUSES = ("confirmed", "placeholder")
# A rejected test token, a proxy challenge, a timeout or a rate limit says nothing
# about the authorization boundary, so these can never be declared as a denial.
NEVER_A_DENIAL = frozenset({401, 407, 408, 429})
EXPECT_KEYS = frozenset({"status", "content_type", "body_contains", "body_not_contains", "json_fields"})

_ID_RE = re.compile(r"[a-z][a-z0-9_]{1,60}")
_TOKEN_KEY_RE = re.compile(r"[a-z][a-z0-9_]{0,40}_token")
_PATH_KEY_RE = re.compile(r"[a-z][a-z0-9_]{0,40}_path")
_PATH_RE = re.compile(r"/[!-~]{0,299}")
# An override pattern is a deliberately tiny language, not general regex:
#   literal text, where the only metacharacter-like items are "\\." and "\\?";
#   variable parts are a class made of A-Z / a-z / 0-9 / _ / - with a mandatory
#   bounded repeat, and each one is followed by a separator that cannot be in a
#   class (or by the end).
# No ".", "*", "+", bare "?", groups, alternation, negated classes or free ranges.
# Matching is therefore deterministic (no backtracking), and a value can never
# contain "/", "..", "%", "?", "#", ";", "@" or whitespace unless the profile
# spelled that character out literally.
_OV_LIT = r"(?:[A-Za-z0-9/_=&~:,-]|\\[.?])"
_OV_SEP = r"(?:[/=&~:,]|\\[.?])"
# the class is spelled in ONE fixed order with "-" only as the last character, so
# it can never form a range other than A-Z, a-z, 0-9 (e.g. no "[--0-9]", which
# Python would read as the range "-" .. "0" and which contains "." and "/")
_OV_CLASS = r"\[(?=[^\]])(?:A-Z)?(?:a-z)?(?:0-9)?_?-?\]\{[0-9]{1,3}(?:,[0-9]{1,3})?\}"
_SAFE_OVERRIDE_PATTERN = re.compile(
    rf"{_OV_LIT}+(?:{_OV_CLASS}{_OV_SEP}{_OV_LIT}*)*(?:{_OV_CLASS})?")
_HOST_RE = re.compile(r"[a-z0-9]([a-z0-9.-]{0,251}[a-z0-9])?")
_HEADER_NAME_RE = re.compile(r"[A-Za-z0-9-]{1,64}")
_HEADER_VALUE_RE = re.compile(r"[ -~]{0,200}")
_RESERVED_HEADERS = frozenset({"authorization", "host", "cookie", "content-length", "transfer-encoding"})


class RuleError(ValueError):
    """A profile file is malformed. Raised at load time, never at run time."""


def _need(cond: bool, where: str, msg: str) -> None:
    if not cond:
        raise RuleError(f"L2 profile {where}: {msg}")


def _str_list(value, where: str, name: str, *, required: bool) -> list[str]:
    if value is None and not required:
        return []
    _need(isinstance(value, list) and all(isinstance(x, str) and x for x in value),
          where, f"`{name}` must be a list of non-empty strings")
    _need(bool(value) or not required, where, f"`{name}` must not be empty")
    return list(value)


def _validate_expect(raw, where: str, *, need_content: bool) -> dict:
    _need(isinstance(raw, dict), where, "must be an object")
    unknown = set(raw) - EXPECT_KEYS
    _need(not unknown, where, f"unknown keys {sorted(unknown)}")
    status = raw.get("status")
    _need(isinstance(status, list) and status
          and all(isinstance(s, int) and not isinstance(s, bool) and 100 <= s <= 599 for s in status),
          where, "`status` must be a non-empty list of HTTP status codes")
    out: dict = {"status": sorted(set(status))}
    if "content_type" in raw:
        _need(isinstance(raw["content_type"], str) and raw["content_type"], where,
              "`content_type` must be a non-empty string")
        out["content_type"] = raw["content_type"].lower()
    for key in ("body_contains", "body_not_contains"):
        vals = _str_list(raw.get(key), where, key, required=False)
        if vals:
            out[key] = vals
    if "json_fields" in raw:
        jf = raw["json_fields"]
        _need(isinstance(jf, dict) and jf and all(
            isinstance(k, str) and k and isinstance(v, (str, int, float, bool)) or v is None
            for k, v in jf.items()), where, "`json_fields` must map dotted paths to scalar values")
        out["json_fields"] = dict(jf)
    if need_content:
        _need("body_contains" in out or "json_fields" in out, where,
              "must check response content (`body_contains` or `json_fields`), not only the status")
    return out


def _validate_request(raw, where: str, tokens: dict, paths: dict) -> dict:
    _need(isinstance(raw, dict), where, "must be an object")
    _need(raw.get("token") in tokens, where, f"`token` must be one of {sorted(tokens)}")
    _need(raw.get("path") in paths, where, f"`path` must be one of {sorted(paths)}")
    headers = raw.get("headers", {})
    _need(isinstance(headers, dict), where, "`headers` must be an object")
    for k, v in headers.items():
        _need(isinstance(k, str) and _HEADER_NAME_RE.fullmatch(k) is not None
              and k.lower() not in _RESERVED_HEADERS, where, f"header name {k!r} is not allowed")
        _need(isinstance(v, str) and _HEADER_VALUE_RE.fullmatch(v) is not None, where,
              f"header value for {k!r} is not allowed")
    return {"token": raw["token"], "path": raw["path"], "headers": dict(headers)}


def _validate_check(raw, where: str, tokens: dict, paths: dict) -> dict:
    _need(isinstance(raw, dict), where, "must be an object")
    cid = raw.get("id")
    _need(isinstance(cid, str) and _ID_RE.fullmatch(cid) is not None, where, "`id` is invalid")
    where = f"{where} ({cid})"
    for key in ("category", "label"):
        _need(isinstance(raw.get(key), str) and raw[key].strip(), where, f"`{key}` is required")

    finding = raw.get("finding")
    _need(isinstance(finding, dict), where, "`finding` must be an object")
    for key in ("id", "title", "category", "summary", "impact", "how_to_verify"):
        _need(isinstance(finding.get(key), str) and finding[key].strip(), where, f"`finding.{key}` is required")
    _need(finding.get("severity") in SEVERITIES, where, f"`finding.severity` must be one of {SEVERITIES}")
    steps = _str_list(finding.get("steps"), where, "finding.steps", required=True)

    subject = _validate_request(raw.get("subject"), f"{where} subject", tokens, paths)

    pres_raw = raw.get("preconditions")
    _need(isinstance(pres_raw, list) and pres_raw, where,
          "`preconditions` must list at least one positive control; a denial without one proves nothing")
    pres, names = [], set()
    for i, p in enumerate(pres_raw):
        pw = f"{where} preconditions[{i}]"
        req = _validate_request(p, pw, tokens, paths)
        name = p.get("name")
        _need(isinstance(name, str) and _ID_RE.fullmatch(name) is not None and name not in names, pw,
              "`name` must be a unique identifier")
        names.add(name)
        _need(isinstance(p.get("label"), str) and p["label"].strip(), pw, "`label` is required")
        _need((req["token"], req["path"]) != (subject["token"], subject["path"]), pw,
              "must not be the same request as the subject request")
        expect = _validate_expect(p.get("expect"), f"{pw} expect", need_content=True)
        _need(all(200 <= s <= 299 for s in expect["status"]), pw, "a positive control must expect 2xx")
        pres.append({**req, "name": name, "label": p["label"].strip(), "expect": expect})

    # The controls have to be about THIS request, not just any request that works:
    #  (1) the subject's own token must be shown to be valid, so a denial is an
    #      authorization decision and not a rejected credential;
    #  (2) the subject's path must be shown to serve the resource to another,
    #      entitled identity, so a denial is not a wrong path. Where no such
    #      identity can exist (e.g. an expired link nobody can open) the rule must
    #      say why, and then "not found" can never count as a denial.
    _need(any(p["token"] == subject["token"] for p in pres), where,
          "needs a precondition that uses the subject's token (proves the test account is authenticated)")
    has_owner_control = any(p["path"] == subject["path"] and p["token"] != subject["token"] for p in pres)
    control_exception = str(raw.get("owner_control_exception") or "").strip()
    _need(has_owner_control or control_exception, where,
          "needs a precondition on the subject's path with a different account (owner control), "
          "or `owner_control_exception` explaining why none can exist")

    exposed = _validate_expect(raw.get("exposed"), f"{where} exposed", need_content=True)
    _need(all(200 <= s <= 299 for s in exposed["status"]), where, "`exposed.status` must be 2xx")
    _need("body_contains" in exposed, where, "`exposed.body_contains` is required")

    denied = _validate_expect(raw.get("denied"), f"{where} denied", need_content=False)
    _need(all(400 <= s <= 499 and s not in NEVER_A_DENIAL for s in denied["status"]), where,
          f"`denied.status` must be 4xx and must not include {sorted(NEVER_A_DENIAL)}")
    _need(has_owner_control or 404 not in denied["status"], where,
          "without an owner control on the subject's path, 404 cannot be a denial (a wrong path looks the same)")
    missing = set(exposed["body_contains"]) - set(denied.get("body_not_contains", []))
    _need(not missing, where,
          f"`denied.body_not_contains` must include every exposed marker (missing {sorted(missing)})")

    spec_status = raw.get("spec_status", "placeholder")
    _need(spec_status in SPEC_STATUSES, where, f"`spec_status` must be one of {SPEC_STATUSES}")
    evidence = _str_list(raw.get("spec_evidence"), where, "spec_evidence", required=False)
    _need(spec_status != "confirmed" or bool(evidence), where,
          "a confirmed check must list `spec_evidence` (where the API behaviour was read from)")

    return {
        "id": cid,
        "category": raw["category"].strip(),
        "label": raw["label"].strip(),
        "spec_status": spec_status,
        "spec_evidence": evidence,
        "spec_note": str(raw.get("spec_note") or ""),
        "owner_control_exception": control_exception,
        "finding": {
            "id": finding["id"], "title": finding["title"], "severity": finding["severity"],
            "category": finding["category"], "help_term": finding.get("help_term") or "idor",
            "summary": finding["summary"], "impact": finding["impact"],
            "steps": steps, "how_to_verify": finding["how_to_verify"],
        },
        "subject": subject,
        "preconditions": pres,
        "denied": denied,
        "exposed": exposed,
    }


def validate_profile(raw, source: str = "<profile>") -> dict:
    """Return a normalized profile or raise `RuleError`."""
    _need(isinstance(raw, dict), source, "must be a JSON object")
    pid = raw.get("id")
    _need(isinstance(pid, str) and _ID_RE.fullmatch(pid) is not None, source, "`id` is invalid")
    where = f"{source} ({pid})"
    _need(isinstance(raw.get("label"), str) and raw["label"].strip(), where, "`label` is required")

    applies = raw.get("applies_to")
    _need(isinstance(applies, dict), where, "`applies_to` must be an object")
    hosts = [h.rstrip(".").lower() for h in _str_list(applies.get("hosts"), where, "applies_to.hosts", required=False)]
    _need(all(_HOST_RE.fullmatch(h) for h in hosts), where, "`applies_to.hosts` contains an invalid hostname")

    tokens_raw, paths_raw = raw.get("tokens"), raw.get("paths")
    _need(isinstance(tokens_raw, dict) and tokens_raw, where, "`tokens` must be a non-empty object")
    _need(isinstance(paths_raw, dict) and paths_raw, where, "`paths` must be a non-empty object")
    tokens: dict[str, dict] = {}
    for k, v in tokens_raw.items():
        _need(_TOKEN_KEY_RE.fullmatch(str(k)) is not None, where, f"token key {k!r} must end with `_token`")
        _need(isinstance(v, dict) and isinstance(v.get("label"), str) and v["label"].strip(), where,
              f"`tokens.{k}.label` is required")
        tokens[k] = {"label": v["label"].strip()}
    paths: dict[str, dict] = {}
    for k, v in paths_raw.items():
        _need(_PATH_KEY_RE.fullmatch(str(k)) is not None, where, f"path key {k!r} must end with `_path`")
        _need(isinstance(v, dict) and isinstance(v.get("label"), str) and v["label"].strip(), where,
              f"`paths.{k}.label` is required")
        _need(isinstance(v.get("default"), str) and _PATH_RE.fullmatch(v["default"]) is not None, where,
              f"`paths.{k}.default` must be an absolute ASCII path without spaces")
        pattern = v.get("override_pattern")
        if pattern is not None:
            # An operator may replace this path (e.g. with the id of their mock
            # resource), but only with something the profile - and so the admin who
            # accepted it - allows. Without a pattern the path cannot be overridden.
            _need(isinstance(pattern, str) and 0 < len(pattern) <= 200, where,
                  f"`paths.{k}.override_pattern` must be a regular expression of at most 200 characters")
            # Only literals, escaped characters, positive character classes and bounded
            # repeats: no ".", "*", "+", groups, alternation or negated classes. Such a
            # pattern cannot backtrack catastrophically and cannot quietly allow
            # "anything" (path traversal, extra query parameters).
            _need(_SAFE_OVERRIDE_PATTERN.fullmatch(pattern) is not None, where,
                  f"`paths.{k}.override_pattern` must be literal text with variable parts written as "
                  "[A-Za-z0-9_-]{m,n}, each followed by a separator (/ = & : ~ , \\. \\?) or the end")
            for lo, hi in re.findall(r"\{([0-9]+)(?:,([0-9]+))?\}", pattern):
                # m >= 1: a variable part can never be empty, so two separators (or two
                # dots) written around it can never end up next to each other
                _need(1 <= int(lo) <= int(hi or lo) <= 300, where,
                      f"`paths.{k}.override_pattern` repeat counts must satisfy 1 <= m <= n <= 300")
            _need("\\.\\." not in pattern and "/\\./" not in pattern and not pattern.endswith("/\\."), where,
                  f"`paths.{k}.override_pattern` must not contain '..' or '/./'")
            try:
                compiled = re.compile(pattern)
            except re.error as e:
                raise RuleError(f"L2 profile {where}: `paths.{k}.override_pattern` is not a valid pattern ({e})") from None
            _need(compiled.fullmatch(v["default"]) is not None or "REPLACE_WITH" in v["default"], where,
                  f"`paths.{k}.default` must itself match `override_pattern`")
        paths[k] = {"label": v["label"].strip(), "default": v["default"], "override_pattern": pattern}

    distinct = []
    for pair in raw.get("distinct_tokens", []):
        _need(isinstance(pair, list) and len(pair) == 2 and pair[0] != pair[1]
              and all(p in tokens for p in pair), where, "`distinct_tokens` must be pairs of declared token keys")
        distinct.append(tuple(pair))

    checks_raw = raw.get("checks")
    _need(isinstance(checks_raw, list) and checks_raw, where, "`checks` must be a non-empty list")
    checks = [_validate_check(c, f"{where} checks[{i}]", tokens, paths) for i, c in enumerate(checks_raw)]
    for c in checks:
        # Two roles played by one account would make the comparison meaningless.
        for pre in c["preconditions"]:
            if pre["path"] == c["subject"]["path"] and pre["token"] != c["subject"]["token"]:
                pair = {pre["token"], c["subject"]["token"]}
                _need(any(set(d) == pair for d in distinct), where,
                      f"check {c['id']}: {sorted(pair)} must be listed in `distinct_tokens`")

    return {
        "id": pid,
        "label": raw["label"].strip(),
        # derived, never declared: a profile is only as confirmed as its checks
        "spec_status": ("confirmed" if all(c["spec_status"] == "confirmed" for c in checks)
                        else "partial" if any(c["spec_status"] == "confirmed" for c in checks)
                        else "placeholder"),
        "spec_note": str(raw.get("spec_note") or ""),
        "hosts": hosts,
        "tokens": tokens,
        "paths": paths,
        "distinct_tokens": distinct,
        "checks": checks,
    }


def canonical_json(obj) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def rule_digest(rule_json: str) -> str:
    return hashlib.sha256(rule_json.encode("utf-8")).hexdigest()


def site_profile_dirs(data_dir: Path | None = None) -> list[Path]:
    """Directories whose profiles are SITE configuration, not shipped code:
    `<data_dir>/l2_profiles` and the one named by `VULNIX_L2_PROFILE_DIR`. A site
    profile decides what may be run against a real service, so it is held to more:
    strict file permissions, and an admin has to accept its exact content."""
    dirs: list[Path] = []
    if data_dir is not None and (Path(data_dir) / "l2_profiles").is_dir():
        dirs.append(Path(data_dir) / "l2_profiles")
    extra = os.environ.get(PROFILE_DIR_ENV)
    if extra:
        dirs.append(Path(extra))
    return dirs


def default_profile_dirs(data_dir: Path | None = None) -> list[Path]:
    """Bundled templates, then the installation's own (site) profiles."""
    return [BUILTIN_PROFILE_DIR, *site_profile_dirs(data_dir)]


def site_file_problem(path: Path) -> str | None:
    """Why a site profile file must not be trusted, or None. Anyone who can write
    the file (or swap it via its directory) could make a rule runnable."""
    try:
        st_file = os.lstat(path)
        st_dir = os.stat(path.parent)
    except OSError as e:
        return f"cannot stat: {type(e).__name__}"
    import stat as _stat
    if not _stat.S_ISREG(st_file.st_mode):
        return "not a regular file (symlinks are not followed)"
    uid = os.getuid() if hasattr(os, "getuid") else None
    if uid is not None and (st_file.st_uid != uid or st_dir.st_uid != uid):
        return "file or directory is not owned by the user running the control plane"
    if st_file.st_mode & 0o022:
        return f"file is writable by group or others (mode {oct(st_file.st_mode & 0o777)}); use 0600"
    if st_dir.st_mode & 0o022:
        return f"directory is writable by group or others (mode {oct(st_dir.st_mode & 0o777)}); use 0700"
    return None


class L2RuleSet:
    """All loaded profiles. Check ids, finding ids and hosts are unique across profiles."""

    def __init__(self, profiles: list[dict]):
        self.sources: dict[str, dict] = {}
        self.rejected: list[dict] = []
        self.profiles: dict[str, dict] = {}
        self._checks: dict[str, tuple[dict, dict]] = {}
        self._hosts: dict[str, dict] = {}
        finding_ids: set[str] = set()
        for p in profiles:
            _need(p["id"] not in self.profiles, p["id"], "duplicate profile id")
            self.profiles[p["id"]] = p
            for h in p["hosts"]:
                _need(h not in self._hosts, p["id"], f"host {h} is already bound to another profile")
                self._hosts[h] = p
            for c in p["checks"]:
                _need(c["id"] not in self._checks, p["id"], f"duplicate check id {c['id']}")
                _need(c["finding"]["id"] not in finding_ids, p["id"], f"duplicate finding id {c['finding']['id']}")
                finding_ids.add(c["finding"]["id"])
                self._checks[c["id"]] = (p, c)

    @classmethod
    def load(cls, dirs: list[Path] | None = None, site_dirs: list[Path] | None = None) -> "L2RuleSet":
        """`dirs` are trusted like code (the bundled directory, or directories a
        caller passes in explicitly). `site_dirs` are site configuration: a file
        with unsafe permissions or invalid content is NOT loaded (it is listed in
        `rejected`), and every loaded one is recorded in `sources` with the SHA-256
        of its bytes so the control plane can require an admin's acceptance."""
        if dirs is None:
            dirs = [BUILTIN_PROFILE_DIR]
            site_dirs = site_profile_dirs() if site_dirs is None else site_dirs
        site_dirs = list(site_dirs or [])
        # A later directory replaces a profile with the same id from an earlier one,
        # so a site-specific (private) profile can supersede the bundled template.
        by_id: dict[str, dict] = {}
        sources: dict[str, dict] = {}
        rejected: list[dict] = []
        for d, is_site in [(d, False) for d in dirs] + [(d, True) for d in site_dirs]:
            seen_here: set[str] = set()
            for f in sorted(Path(d).glob("*.json")):
                try:
                    if is_site:
                        problem = site_file_problem(f)
                        if problem:
                            raise RuleError(f"L2 profile {f.name}: {problem}")
                    data = f.read_bytes()
                    try:
                        raw = json.loads(data.decode("utf-8"))
                    except ValueError as e:
                        raise RuleError(f"L2 profile {f.name}: invalid JSON ({e})") from None
                    profile = validate_profile(raw, f.name)
                    _need(profile["id"] not in seen_here, f.name, "duplicate profile id within one directory")
                except RuleError as e:
                    if not is_site:
                        raise                      # shipped/explicit profiles must be valid
                    rejected.append({"file": f.name, "reason": str(e)})
                    continue
                seen_here.add(profile["id"])
                by_id.pop(profile["id"], None)
                by_id[profile["id"]] = profile
                sources[profile["id"]] = {"file": f.name, "directory": str(Path(d)), "site": is_site,
                                          "sha256": hashlib.sha256(data).hexdigest()}
        # Trusted profiles must be consistent among themselves. Site profiles are then
        # added one at a time: one that collides with what is already there (same
        # host, check id or finding id) is rejected on its own, without taking the
        # other - possibly accepted - site profiles down with it.
        kept = [p for pid, p in by_id.items() if not sources[pid]["site"]]
        cls(kept)
        for pid in [pid for pid in by_id if sources[pid]["site"]]:
            try:
                cls(kept + [by_id[pid]])
            except RuleError as e:
                rejected.append({"file": sources[pid]["file"], "reason": str(e)})
                sources.pop(pid)
                continue
            kept.append(by_id[pid])
        return cls(kept)._with(sources={p["id"]: sources[p["id"]] for p in kept}, rejected=rejected)

    def _with(self, *, sources: dict, rejected: list) -> "L2RuleSet":
        self.sources = {**getattr(self, "sources", {}), **sources}
        self.rejected = list(rejected)
        return self

    def hold_unaccepted(self, accepted: dict[str, str]) -> list[str]:
        """Make every check of a site profile non-runnable unless an admin accepted
        exactly this content (`accepted`: profile id -> sha256). Returns the ids
        that are held. Held checks stay listed as candidates."""
        held = []
        for pid, src in self.sources.items():
            if not src["site"] or accepted.get(pid) == src["sha256"]:
                continue
            profile = self.profiles.get(pid)
            if profile is None:
                continue
            held.append(pid)
            for c in profile["checks"]:
                if c["spec_status"] == "confirmed":
                    c["spec_status"] = "unaccepted"
                    c["spec_note"] = ("このプロファイルの内容は管理者にまだ承認されていません"
                                      "（承認後に変更された場合も再承認が必要です）。")
            profile["spec_status"] = "unaccepted"
        return held

    def check_ids(self) -> tuple[str, ...]:
        return tuple(sorted(self._checks))

    def runnable_check_ids(self) -> tuple[str, ...]:
        """Checks whose rule was confirmed against the target API. Only these are
        accepted by the Gateway tool schema."""
        return tuple(sorted(cid for cid, (_, c) in self._checks.items() if c["spec_status"] == "confirmed"))

    def has_check(self, check_id) -> bool:
        return check_id in self._checks

    def profile_for_host(self, host: str | None) -> dict | None:
        return self._hosts.get((host or "").rstrip(".").lower())

    def profile_of_check(self, check_id: str) -> dict | None:
        entry = self._checks.get(check_id)
        return entry[0] if entry else None

    def check(self, check_id: str) -> dict | None:
        entry = self._checks.get(check_id)
        return entry[1] if entry else None

    def token_keys(self) -> set[str]:
        return {k for p in self.profiles.values() for k in p["tokens"]}

    def path_keys(self) -> set[str]:
        return {k for p in self.profiles.values() for k in p["paths"]}

    def worker_rule(self, check_id: str) -> dict:
        """The minimal, text-free rule handed to the sandboxed worker."""
        profile, c = self._checks[check_id]

        def req(node: dict) -> dict:
            return {"token": node["token"], "path_key": node["path"],
                    "path": profile["paths"][node["path"]]["default"], "headers": node["headers"]}

        return {
            "id": c["id"],
            "subject": req(c["subject"]),
            "preconditions": [{**req(p), "name": p["name"], "expect": p["expect"]} for p in c["preconditions"]],
            "denied": c["denied"],
            "exposed": c["exposed"],
        }

    def worker_rule_json(self, check_id: str) -> str:
        return canonical_json(self.worker_rule(check_id))


def tokens_needed(check: dict) -> list[str]:
    out: list[str] = []
    for node in (check["subject"], *check["preconditions"]):
        if node["token"] not in out:
            out.append(node["token"])
    return out


def paths_used(check: dict) -> list[str]:
    out: list[str] = []
    for node in (check["subject"], *check["preconditions"]):
        key = node.get("path_key") or node["path"]
        if key not in out:
            out.append(key)
    return out


def _all_true(checks, expect: dict) -> bool:
    """The worker must have evaluated exactly the conditions the rule declares."""
    wanted = {k for k in expect if k in EXPECT_KEYS}
    return (isinstance(checks, dict) and set(checks) == wanted
            and all(v is True for v in checks.values()))


def evaluate(worker_rule: dict, result: dict | None) -> dict:
    """Control-plane verdict for one worker result.

    Independent of the worker's own verdict: the two have to agree, the rule the
    worker ran has to be byte-identical to the configured one, every declared
    precondition has to have passed, and the subject response has to satisfy the
    full `denied` (or `exposed`) condition set. Anything else is "unverified".
    """
    reasons: list[str] = []
    if not isinstance(result, dict) or result.get("check") != worker_rule["id"]:
        return {"verdict": "unverified", "reasons": ["no_result"]}
    if result.get("rule_digest") != rule_digest(canonical_json(worker_rule)):
        return {"verdict": "unverified", "reasons": ["rule_digest_mismatch"]}

    reported = result.get("preconditions")
    reported = reported if isinstance(reported, list) else []
    by_name = {p.get("name"): p for p in reported if isinstance(p, dict)}
    for pre in worker_rule["preconditions"]:
        got = by_name.get(pre["name"]) or {}
        if not (got.get("performed") is True and got.get("ok") is True
                and got.get("status") in pre["expect"]["status"]
                and _all_true(got.get("checks"), pre["expect"])):
            reasons.append(f"precondition_failed:{pre['name']}")
    if len(reported) != len(worker_rule["preconditions"]):
        reasons.append("precondition_list_mismatch")

    subject = result.get("subject") if isinstance(result.get("subject"), dict) else {}
    status = result.get("status")
    if subject.get("performed") is not True:
        reasons.append("subject_request_not_performed")
        return {"verdict": "unverified", "reasons": reasons}

    exposed, denied = worker_rule["exposed"], worker_rule["denied"]
    if (status in exposed["status"] and _all_true(subject.get("exposed_checks"), exposed)
            and result.get("established") is True and result.get("verdict") == "proven"):
        return {"verdict": "proven", "reasons": []}

    excerpt = result.get("response_text") if isinstance(result.get("response_text"), str) else ""
    if status not in denied["status"]:
        reasons.append(f"status_not_a_denial:{status}")
    if not _all_true(subject.get("denied_checks"), denied):
        reasons.append("denial_content_mismatch")
    if any(m in excerpt for m in exposed["body_contains"]):
        reasons.append("owner_content_in_response")
    if subject.get("identical_to_control") is not False:
        reasons.append("response_identical_to_owner")
    if subject.get("truncated") is not False:
        reasons.append("response_truncated")
    if result.get("established") is not False or result.get("verdict") != "not_reproduced":
        reasons.append("worker_verdict_disagrees")
    if reasons:
        return {"verdict": "unverified", "reasons": reasons}
    return {"verdict": "not_reproduced", "reasons": []}


_REASON_TEXT = {
    "no_result": "Workerの結果を取得できませんでした",
    "rule_digest_mismatch": "Workerが実行した判定ルールが設定と一致しません",
    "precondition_list_mismatch": "前提確認の実行結果がルールと一致しません",
    "subject_request_not_performed": "前提条件を満たせなかったため、権限外アクセスの試行自体を行っていません",
    "denial_content_mismatch": "拒否応答の内容がルールの条件と一致しません",
    "owner_content_in_response": "拒否ステータスですが応答に所有者側のデータが含まれています",
    "response_identical_to_owner": "応答が所有者の正常応答と同一です",
    "response_truncated": "応答が大きすぎて全体を確認できませんでした",
    "worker_verdict_disagrees": "Workerの判定と一致しません",
}


def explain(check: dict, result: dict | None, outcome: dict) -> str:
    """Japanese one-paragraph note for the finding card and the audit trail."""
    status = (result or {}).get("status")
    shown = f"HTTP {status}" if status is not None else "応答なし"
    pre_labels = "・".join(p["label"] for p in check["preconditions"])
    if outcome["verdict"] == "proven":
        return (f"{shown} の応答に、権限のない検証用アカウントからは見えてはならない模擬データを確認しました。"
                "防御を確認できていません。")
    if outcome["verdict"] == "not_reproduced":
        return (f"権限のない検証用アカウントのアクセスは {shown} で拒否され、応答に所有者側のデータは含まれていませんでした。"
                f"同じ実行内で前提（{pre_labels}）も確認済みです。今回の条件に限った結果です。")
    parts = []
    labels = {p["name"]: p["label"] for p in check["preconditions"]}
    for r in outcome["reasons"]:
        key, _, arg = r.partition(":")
        if key == "precondition_failed":
            parts.append(f"前提「{labels.get(arg, arg)}」を確認できませんでした")
        elif key == "status_not_a_denial":
            parts.append(f"HTTP {arg} はこの項目の拒否応答として定義されていません")
        else:
            parts.append(_REASON_TEXT.get(key, key))
    return (f"判定できず（{shown}）。" + "／".join(parts)
            + "。拒否が防御によるものか、パス・トークン・模擬データの不備によるものかを区別できないため、再現せずとは判定しません。")
