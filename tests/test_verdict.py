import pytest

from app.models.schemas import CheckResult, Verdict
from app.services.verdict import calculate_verdict


def test_verdict_original_when_all_checks_pass() -> None:
    checks = [
        CheckResult(name="a", passed=True, weight=0.5, details="ok"),
        CheckResult(name="b", passed=True, weight=0.5, details="ok"),
    ]
    verdict, confidence, reasons = calculate_verdict(checks)
    assert verdict == Verdict.ORIGINAL
    assert reasons == []
    assert confidence > 0.5


def test_verdict_suspicious_on_partial_failures() -> None:
    checks = [
        CheckResult(name="a", passed=False, weight=0.4, details="fail"),
        CheckResult(name="b", passed=True, weight=0.6, details="ok"),
    ]
    verdict, _, reasons = calculate_verdict(checks)
    assert verdict == Verdict.SUSPICIOUS
    assert len(reasons) == 1


def test_verdict_fake_on_many_failures() -> None:
    checks = [
        CheckResult(name="a", passed=False, weight=0.4, details="fail1"),
        CheckResult(name="b", passed=False, weight=0.4, details="fail2"),
        CheckResult(name="c", passed=False, weight=0.2, details="fail3"),
    ]
    verdict, _, reasons = calculate_verdict(checks)
    assert verdict == Verdict.FAKE
    assert len(reasons) == 3


def test_verdict_unknown_without_checks() -> None:
    verdict, confidence, reasons = calculate_verdict([])
    assert verdict == Verdict.UNKNOWN
    assert confidence == 0.0
    assert reasons
