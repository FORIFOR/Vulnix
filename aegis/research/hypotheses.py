from dataclasses import dataclass


@dataclass(frozen=True)
class Hypothesis:
    hypothesis_id: str
    category: str
    summary: str
    affected_nodes: tuple[str, ...]
    evidence_ids: tuple[str, ...]
    assumptions: tuple[str, ...]
    counter_evidence: tuple[str, ...]
    validation_strategy: str
    confidence: float
    uncertainties: tuple[str, ...]
    verdict: str = "unverified"
