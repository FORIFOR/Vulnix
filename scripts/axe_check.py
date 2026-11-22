"""WCAG 2.1 A/AA checks with axe-core in the browser E2E scripts.

axe-core comes from the web lockfile (web/node_modules/axe-core, installed by `npm ci`):
no network, no extra download. A screen passes when axe reports no serious or critical
violation; every violation (any impact) is kept in the report for review.
"""
from __future__ import annotations

from pathlib import Path

AXE = Path(__file__).resolve().parents[1] / "web/node_modules/axe-core/axe.min.js"
TAGS = ["wcag2a", "wcag2aa", "wcag21a", "wcag21aa"]


def run_axe(page, scope: str | None = None) -> list[dict]:
    page.add_script_tag(content=AXE.read_text(encoding="utf-8"))
    return page.evaluate(
        """async ([scope, tags]) => {
             const r = await axe.run(scope ? document.querySelector(scope) : document,
                                     { runOnly: { type: 'tag', values: tags } });
             return r.violations.map(v => ({ id: v.id, impact: v.impact, help: v.help,
               nodes: v.nodes.slice(0, 3).map(n => n.target.join(' ') + ' :: ' + n.html.slice(0, 160)) }));
           }""", [scope, TAGS])


def gate(found: dict[str, list[dict]]) -> tuple[int, bool]:
    """(screens checked, True when none has a serious or critical violation)."""
    serious = {name: [v for v in vs if v["impact"] in ("serious", "critical")] for name, vs in found.items()}
    return len(found), bool(found) and not any(serious.values())
