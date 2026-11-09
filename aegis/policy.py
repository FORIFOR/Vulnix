"""Layer 2 Policy: tool registry, strict proposal schema, budget.

A proposal is plain data from the model. Unknown keys are rejected, so a model
(or a prompt injected via a scanned web page) cannot smuggle in fields such as
"approved", "scope" or "token".
"""
from __future__ import annotations

import re
import threading
from dataclasses import dataclass
from typing import Callable


class PolicyError(Exception):
    pass


@dataclass(frozen=True)
class ArgSpec:
    type: type
    required: bool = True
    pattern: str | None = None
    choices: tuple | None = None
    max_len: int = 2048


@dataclass(frozen=True)
class Tool:
    name: str
    action: str                                  # action kind this tool performs
    args: dict[str, ArgSpec]
    build_argv: Callable[[dict, dict], list[str]]  # (args, pinned_destination) -> argv
    timeout_s: float = 30.0


PROPOSAL_KEYS = {"tool", "target_id", "action", "args", "rationale"}


def validate_proposal(proposal: object, tools: dict[str, Tool]) -> tuple[Tool, dict]:
    if not isinstance(proposal, dict):
        raise PolicyError("proposal must be an object")
    extra = set(proposal) - PROPOSAL_KEYS
    if extra:
        raise PolicyError(f"unknown proposal fields: {sorted(extra)}")
    for k in ("tool", "target_id", "action", "args"):
        if k not in proposal:
            raise PolicyError(f"missing field: {k}")
    tool = tools.get(proposal["tool"])
    if tool is None:
        raise PolicyError("tool not allowed")
    if proposal["action"] != tool.action:
        raise PolicyError("action does not match tool")
    args = proposal["args"]
    if not isinstance(args, dict):
        raise PolicyError("args must be an object")
    extra = set(args) - set(tool.args)
    if extra:
        raise PolicyError(f"unknown args: {sorted(extra)}")
    for name, spec in tool.args.items():
        if name not in args:
            if spec.required:
                raise PolicyError(f"missing arg: {name}")
            continue
        v = args[name]
        if type(v) is not spec.type:
            raise PolicyError(f"arg {name} wrong type")
        if isinstance(v, str):
            if len(v) > spec.max_len or "\x00" in v:
                raise PolicyError(f"arg {name} invalid")
            if spec.pattern and not re.fullmatch(spec.pattern, v):
                raise PolicyError(f"arg {name} does not match pattern")
        if spec.choices is not None and v not in spec.choices:
            raise PolicyError(f"arg {name} not in allowed choices")
    return tool, args


class Budget:
    def __init__(self, max_actions: int):
        self._left = max_actions
        self._lock = threading.Lock()

    def spend(self) -> None:
        with self._lock:
            if self._left <= 0:
                raise PolicyError("action budget exhausted")
            self._left -= 1
