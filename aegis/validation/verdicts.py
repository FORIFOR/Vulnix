from dataclasses import dataclass


@dataclass(frozen=True)
class Verdict:
    hypothesis_id: str
    status: str
    cross_tenant_exposed: bool
    same_tenant_works: bool
    evidence_ids: tuple[str, ...]
    environment: str
