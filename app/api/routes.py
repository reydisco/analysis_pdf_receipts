from typing import List, Tuple

from fastapi import APIRouter, File, HTTPException, UploadFile, status

from app.config import ALLOWED_CONTENT_TYPE, MAX_FILE_SIZE_BYTES
from app.models.schemas import AnalysisReport, CheckReceiptResponse, ErrorResponse
from app.services.analyzer import ReceiptAnalyzer
from app.storage.report_store import ReportStore

router = APIRouter()
analyzer = ReceiptAnalyzer()
report_store = ReportStore()


@router.post(
    "/check-receipt/",
    response_model=CheckReceiptResponse,
    responses={400: {"model": ErrorResponse}, 413: {"model": ErrorResponse}},
    summary="Запуск анализа PDF-чеков",
)
async def check_receipt(files: List[UploadFile] = File(...)) -> CheckReceiptResponse:
    if not files:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Не передано ни одного файла",
        )

    prepared: List[Tuple[str, bytes]] = []
    for upload in files:
        filename = upload.filename or "unknown.pdf"
        if not filename.lower().endswith(".pdf"):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Файл '{filename}' не является PDF",
            )

        content_type = upload.content_type or ""
        if content_type and content_type not in (ALLOWED_CONTENT_TYPE, "application/octet-stream"):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Недопустимый content-type для '{filename}': {content_type}",
            )

        content = await upload.read()
        if not content:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Файл '{filename}' пустой",
            )
        if len(content) > MAX_FILE_SIZE_BYTES:
            raise HTTPException(
                status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                detail=f"Файл '{filename}' превышает лимит {MAX_FILE_SIZE_BYTES // (1024 * 1024)} MB",
            )

        prepared.append((filename, content))

    analysis_id = report_store.create_id()
    results = analyzer.analyze_files(prepared)
    report = report_store.build_report(analysis_id=analysis_id, file_results=results)
    report_store.save(report)

    return CheckReceiptResponse(
        analysis_id=analysis_id,
        status=report.status,
        files=[item.filename for item in results],
    )


@router.get(
    "/receipt/{analysis_id}",
    response_model=AnalysisReport,
    responses={404: {"model": ErrorResponse}},
    summary="Получение результата анализа",
)
async def get_receipt_analysis(analysis_id: str) -> AnalysisReport:
    report = report_store.get(analysis_id)
    if report is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Анализ с id '{analysis_id}' не найден",
        )
    return report
