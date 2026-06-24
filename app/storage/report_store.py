import json
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional

from app.config import REPORTS_DIR
from app.models.schemas import AnalysisReport, AnalysisStatus


class ReportStore:
    def __init__(self, reports_dir: Optional[Path] = None) -> None:
        self.reports_dir = reports_dir or REPORTS_DIR
        self.reports_dir.mkdir(parents=True, exist_ok=True)

    def create_id(self) -> str:
        return str(uuid.uuid4())

    def save(self, report: AnalysisReport) -> AnalysisReport:
        path = self.reports_dir / f"{report.analysis_id}.json"
        with path.open("w", encoding="utf-8") as file:
            json.dump(report.model_dump(mode="json"), file, ensure_ascii=False, indent=2)
        return report

    def get(self, analysis_id: str) -> Optional[AnalysisReport]:
        path = self.reports_dir / f"{analysis_id}.json"
        if not path.exists():
            return None
        with path.open(encoding="utf-8") as file:
            data = json.load(file)
        return AnalysisReport.model_validate(data)

    def build_report(
        self,
        analysis_id: str,
        file_results: list,
        status: AnalysisStatus = AnalysisStatus.COMPLETED,
        error: Optional[str] = None,
    ) -> AnalysisReport:
        return AnalysisReport(
            analysis_id=analysis_id,
            status=status,
            created_at=datetime.now(timezone.utc),
            files=file_results,
            error=error,
        )
