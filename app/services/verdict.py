from typing import List, Tuple

from app.config import FAKE_THRESHOLD, SUSPICIOUS_THRESHOLD
from app.models.schemas import CheckResult, Verdict


CRITICAL_CHECKS = frozenset({
    "metadata_producer",
    "structure_layout",
    "structure_date_tm",
    "structure_images",
    "structure_file_fingerprint",
    "structure_generator",
})


def calculate_verdict(checks: List[CheckResult]) -> Tuple[Verdict, float, List[str]]:
    if not checks:
        return Verdict.UNKNOWN, 0.0, ["Проверки не выполнены"]

    total_weight = sum(check.weight for check in checks)
    failed_weight = sum(check.weight for check in checks if not check.passed)
    risk_score = failed_weight / total_weight if total_weight else 0.0

    critical_failed = any(
        not check.passed and check.name in CRITICAL_CHECKS for check in checks
    )
    if critical_failed:
        risk_score = max(risk_score, SUSPICIOUS_THRESHOLD)

    reasons = [check.details for check in checks if not check.passed]

    if risk_score >= FAKE_THRESHOLD:
        verdict = Verdict.FAKE
    elif risk_score >= SUSPICIOUS_THRESHOLD:
        verdict = Verdict.SUSPICIOUS
    else:
        verdict = Verdict.ORIGINAL

    confidence = round(abs(risk_score - 0.5) * 2, 2)
    if verdict == Verdict.ORIGINAL:
        confidence = round(1 - risk_score, 2)

    return verdict, confidence, reasons
