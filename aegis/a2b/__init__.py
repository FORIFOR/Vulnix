"""A2B (App-to-Backend) static diagnosis, initial release.

Owner-provided Android apps (APK) or source trees are read statically to list the
backend API attack surface. Nothing here opens a network connection, executes app
code, or treats a discovered API as permission to contact it: every host still has
to go through Vulnix's ownership verification and scope approval, and only then the
existing Gateway / Worker path (real sites: read-only L1 only).

  manifest.py            upload record (hash, owner, size) and input limits
  static_analyzer.py     bounded zip/dex/text reading; URL, path, method, auth and secret hints
  endpoint_inventory.py  normalised endpoints, OpenAPI comparison
  risk_mapper.py         candidate risk classes -> what may happen next (never a verdict)
  report.py              deterministic report; secrets only as kind + fingerprint
"""
from .report import analyze_app  # noqa: F401
