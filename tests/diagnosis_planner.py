"""Test-only planners for the diagnosis loop (no real model).

`steps_from_facts(text)` reads ONLY what Vulnix gave the planner - the "Vulnix
observation / hypothesis" facts in a request or in the model's messages - and
answers with id-only contract steps. It never sees the lab mode, the truth table
or a response body. It is a scripted stand-in, so nothing it does measures the
quality of a real model.
"""
from __future__ import annotations

import json
import re

from aegis.diagnosis_judge import fixed_rule_steps

_FACT = re.compile(r"Vulnix (observation|hypothesis) (?=\{)")
_DECODER = json.JSONDecoder()


def view_from_text(text: str) -> dict:
    obs, hyps, gens = {}, {}, [0]
    # facts may arrive JSON-escaped once (inside a tool result) or more
    texts, t = [text], text
    for _ in range(3):
        t = t.replace('\\"', '"')
        texts.append(t)
    for m, src in ((m, src) for src in texts for m in _FACT.finditer(src)):
        try:
            value, _ = _DECODER.raw_decode(src, m.end())
        except ValueError:
            continue
        if not isinstance(value, dict):
            continue
        need = ("evidence_id", "target_ref", "generation") if m.group(1) == "observation" else (
            "id", "state", "claim", "target_ref", "purpose", "generation")
        if not all(k in value for k in need):
            continue                       # a shortened or foreign fact: not used
        if m.group(1) == "observation" and "evidence_id" in value:
            obs[value["evidence_id"]] = value
        elif m.group(1) == "hypothesis" and "id" in value:
            hyps[value["id"]] = value
        if isinstance(value.get("generation"), int):
            gens.append(value["generation"])
    return {"generation": max(gens), "observations": list(obs.values()),
            "hypotheses": sorted(hyps.values(), key=lambda h: int(h["id"][1:]))}


def steps_from_facts(text: str) -> list[dict]:
    """Prefer the hypothesis with the strongest consequence (another account's data),
    then fall back to the table. Same catalog, same evidence rules as the fixed rule."""
    view = view_from_text(text)
    order = {"other_account_read": 0, "unauthenticated_exposure": 1, "intended_public": 2}
    view["hypotheses"] = sorted(view["hypotheses"], key=lambda h: order.get(h["claim"], 9))
    return fixed_rule_steps(view)


def intents_from_facts(text: str, asset_id: int = 1) -> list[dict]:
    return [{"summary": json.dumps(s, sort_keys=True), "asset_ids": [asset_id], "priority": 7}
            for s in steps_from_facts(text)]
