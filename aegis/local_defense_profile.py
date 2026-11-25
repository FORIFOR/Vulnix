"""Install bounded, locally reviewed defence profiles for a single organization."""

from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import sys

from .local_defense_node import _copy_bounded
from .workers.local_defense import read_reviewed, sha256


ID = re.compile(r"[a-z][a-z0-9-]{0,47}")
HEX = re.compile(r"[0-9a-f]{64}")
FILE = re.compile(r"(?:[A-Za-z0-9_-]+/)*[A-Za-z0-9_-]+\.(?:py|cjs|js|json)")
CHECKS = frozenset({"authentication", "authorization", "tenant-selection", "webhook-signature", "ai-policy", "mfa"})
DRIVERS = {"python": "local_defense_probe.py", "node": "local_defense_probe.cjs"}
ENTRY = {"python": "check.py", "node": "check.cjs"}
MAX_RUNTIME_BYTES = 140 << 20


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()


def validate_manifest(manifest):
    if (not isinstance(manifest, dict)
            or set(manifest) != {"version", "id", "language", "title", "revision", "files", "checks"}
            or type(manifest["version"]) is not int or manifest["version"] != 1):
        raise ValueError("unsupported defence profile schema")
    lang = manifest["language"]
    if not isinstance(lang, str) or lang not in ENTRY or not isinstance(manifest["id"], str) or not ID.fullmatch(manifest["id"]):
        raise ValueError("unsupported defence profile identity")
    for name in ("title", "revision"):
        value = manifest[name]
        if not isinstance(value, str) or not 1 <= len(value) <= 100 or not value.isprintable():
            raise ValueError("invalid profile display field")
    files = manifest["files"]
    if (not isinstance(files, dict) or not 1 <= len(files) <= 32 or ENTRY[lang] not in files
            or any(not FILE.fullmatch(name) or any(part.lower().startswith("data") or part == "node_modules"
                                                 for part in name.split("/")[:-1])
                   or len(name) > 128 or not isinstance(digest, str) or not HEX.fullmatch(digest)
                   for name, digest in files.items())):
        raise ValueError("invalid reviewed file closure")
    checks = manifest["checks"]
    if not isinstance(checks, dict) or not checks or not checks.keys() <= CHECKS:
        raise ValueError("unsupported defence checks")
    for pair in checks.values():
        if (not isinstance(pair, dict) or set(pair) != {"allow", "deny"}
                or any(not isinstance(item, dict) for item in pair.values())
                or _canonical(pair["allow"]) == _canonical(pair["deny"]) or len(_canonical(pair)) > 4096):
            raise ValueError("each check needs different synthetic allow and deny inputs")
    return manifest


def case_verdicts(manifest, observations):
    verdicts = {}
    for category in manifest["checks"]:
        pair = observations.get(category) if isinstance(observations, dict) else None
        if (not isinstance(pair, dict) or set(pair) != {"allow", "deny"}
                or any(type(value) is not bool for value in pair.values())):
            verdicts[category] = "unverified"
        elif pair == {"allow": True, "deny": False}:
            verdicts[category] = "passed"
        else:
            verdicts[category] = "failed"
    return verdicts


def _private(path: Path):
    info = path.lstat()
    if path.is_symlink() or info.st_uid not in (0, os.geteuid()) or info.st_mode & 0o022:
        raise ValueError("review registry and bundles must be controlled by the server operator")


def _driver(language):
    return Path(__file__).with_name("workers") / DRIVERS[language]


@dataclass(frozen=True)
class PortableProfile:
    bundle: Path
    manifest_digest: str
    runtime: Path
    runtime_digest: str

    @classmethod
    def load(cls, bundle: Path, digest: str, node: Path | None, node_sha256: str | None):
        _private(bundle)
        reviewed = validate_manifest(json.loads(read_reviewed(bundle, "profile.json", digest)))
        if reviewed["language"] == "node":
            if node is None or node_sha256 is None:
                raise ValueError("Node profiles require an explicitly pinned runtime")
            return cls(bundle, digest, node, node_sha256)
        runtime = Path(sys.executable).resolve()
        with runtime.open("rb") as handle:
            return cls(bundle, digest, runtime, hashlib.file_digest(handle, "sha256").hexdigest())

    def manifest(self):
        return validate_manifest(json.loads(read_reviewed(self.bundle, "profile.json", self.manifest_digest)))

    def plan(self):
        manifest = self.manifest()
        language = manifest["language"]
        return {
            "id": "profile-" + manifest["id"],
            "test": manifest["title"], "review_revision": manifest["revision"],
            "environment": "linux-namespaces-cgroup-seccomp/" + language,
            "timeout_seconds": 15, "memory_bytes": 384 << 20, "max_processes": 32,
            "manifest_sha256": self.manifest_digest, "runtime_sha256": self.runtime_digest,
            "driver_sha256": sha256(_driver(language).read_bytes()),
            "conditions": sorted(manifest["checks"]), "automatic_verdict": True,
        }

    def stage(self, snapshot, plan, permit):
        manifest = self.manifest()
        snapshot.mkdir()
        source = snapshot / "source"
        source.mkdir()
        for name, digest in manifest["files"].items():
            if permit:
                permit()
            dest = source / name
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_bytes(read_reviewed(self.bundle, "source/" + name, digest))
        driver = _driver(manifest["language"]).read_bytes()
        if sha256(driver) != plan["driver_sha256"]:
            raise ValueError("reviewed driver changed")
        harness = snapshot / ("probe.cjs" if manifest["language"] == "node" else "probe.py")
        harness.write_bytes(driver)
        (snapshot / "cases.json").write_bytes(_canonical(manifest["checks"]))
        native_node = None
        if manifest["language"] == "node":
            native_node = snapshot / "node"
            fd = os.open(self.runtime.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            try:
                digest, _ = _copy_bounded(fd, self.runtime.name, native_node, MAX_RUNTIME_BYTES)
            finally:
                os.close(fd)
        else:
            with self.runtime.open("rb") as handle:
                digest = hashlib.file_digest(handle, "sha256").hexdigest()
        if digest != self.runtime_digest:
            raise ValueError("reviewed runtime changed")
        for directory, _, files in os.walk(snapshot, topdown=False):
            for name in files:
                path = Path(directory) / name
                path.chmod(0o555 if path == native_node else 0o444)
            Path(directory).chmod(0o555)
        if native_node:
            return [sys.executable, "-I", "-c", "import os,sys; os.execv(sys.argv[1],sys.argv[1:])",
                    str(native_node), "--no-warnings", "--experimental-permission", f"--allow-fs-read={snapshot}",
                    str(harness), str(snapshot)]
        return [str(self.runtime), "-I", "-B", str(harness), str(snapshot)]


def load_registry(path):
    """Read deployment-controlled manifests. No browser endpoint accepts paths or code."""
    from .tenancy import valid_org_id

    path = path.absolute()
    _private(path.parent)
    _private(path)
    if not stat.S_ISREG(path.lstat().st_mode) or path.stat().st_size > 32 * 1024:
        raise ValueError("invalid defence registry file")
    entries = json.loads(path.read_bytes())
    if not isinstance(entries, list) or len(entries) > 32:
        raise ValueError("invalid defence registry size")
    results = {}
    for entry in entries:
        if (not isinstance(entry, dict) or set(entry) != {"org", "bundle", "sha256", "node"}
                or not isinstance(entry["org"], str) or not valid_org_id(entry["org"])
                or not isinstance(entry["bundle"], str) or not ID.fullmatch(entry["bundle"])
                or not isinstance(entry["sha256"], str) or not HEX.fullmatch(entry["sha256"])):
            raise ValueError("invalid defence registry entry")
        node = entry["node"]
        runtime = digest = None
        if node is not None:
            if (not isinstance(node, dict) or set(node) != {"path", "sha256"}
                    or not isinstance(node["path"], str) or not Path(node["path"]).is_absolute()
                    or not isinstance(node["sha256"], str) or not HEX.fullmatch(node["sha256"])):
                raise ValueError("invalid Node runtime registration")
            runtime, digest = Path(node["path"]).resolve(strict=True), node["sha256"]
        profile = PortableProfile.load(path.parent / entry["bundle"], entry["sha256"], runtime, digest)
        group = results.setdefault(entry["org"], {})
        name = profile.plan()["id"]
        if name in group or len(group) >= 8:
            raise ValueError("duplicated or too many defence profiles for the organization")
        group[name] = profile
    return results
