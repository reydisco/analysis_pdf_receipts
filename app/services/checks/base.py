from abc import ABC, abstractmethod

from app.models.schemas import CheckResult, PdfExtractResult


class BaseCheck(ABC):
    name: str
    weight: float

    @abstractmethod
    def run(self, extracted: PdfExtractResult, text_lower: str) -> CheckResult:
        pass
