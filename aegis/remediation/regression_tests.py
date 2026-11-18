"""The fixed synthetic harness in validation/test_generator.py covers both orgs."""
from .patch_validator import PatchResult


def regression_passed(result: PatchResult) -> bool:
    return result.fixed and result.same_tenant_preserved
