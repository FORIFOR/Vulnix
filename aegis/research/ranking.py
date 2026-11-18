from .hypotheses import Hypothesis


def rank(items: tuple[Hypothesis, ...]) -> tuple[Hypothesis, ...]:
    return tuple(sorted(items, key=lambda item: (-item.confidence, item.hypothesis_id)))
