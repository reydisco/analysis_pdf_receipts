import io
import re
from typing import Any, List, Optional

import fitz
import pdfplumber
from pypdf import PdfReader

from app.models.schemas import PdfExtractResult
from app.services.layer_extractor import extract_layers
from app.services.ocr_extractor import ocr_pdf_text
from app.services.stream_analyzer import analyze_pdf_streams, generator_fingerprint

SUSPICIOUS_PRODUCERS = [
    "microsoft print to pdf",
    "microsoft word",
    "libreoffice",
    "canva",
    "photoshop",
    "adobe illustrator",
    "wkhtmltopdf",
    "google docs",
    "smallpdf",
]


def extract_pdf(pdf_bytes: bytes) -> PdfExtractResult:
    result = PdfExtractResult()

    try:
        reader = PdfReader(io.BytesIO(pdf_bytes))
        meta = reader.metadata or {}

        result.page_count = len(reader.pages)
        result.encrypted = reader.is_encrypted
        result.pdf_version = getattr(reader, "pdf_header", None)
        if result.pdf_version and result.pdf_version.startswith("%PDF-"):
            result.pdf_version = result.pdf_version.replace("%PDF-", "")

        result.metadata = {
            "producer": _normalize(meta.get("/Producer")),
            "creator": _normalize(meta.get("/Creator")),
            "author": _normalize(meta.get("/Author")),
            "creation_date": _normalize(meta.get("/CreationDate")),
            "mod_date": _normalize(meta.get("/ModDate")),
            "title": _normalize(meta.get("/Title")),
        }

        result.has_javascript = _detect_javascript(reader)
        result.has_forms = _detect_forms(reader)
        result.has_attachments = _detect_attachments(reader)
        result.embedded_fonts = _extract_fonts(reader)
        result.text = _extract_text(pdfplumber.open(io.BytesIO(pdf_bytes)))
        result.text_extractable = len(result.text.strip()) > 20
        result.ocr_used = False
        if not result.text_extractable:
            ocr_text, ocr_ok = ocr_pdf_text(pdf_bytes)
            if ocr_ok:
                result.text = ocr_text
                result.text_extractable = True
                result.ocr_used = True
        result.image_only = _detect_image_only(pdf_bytes, result.text_extractable)

        layers = extract_layers(
            pdf_bytes,
            result.text,
            result.metadata.get("creation_date"),
        )
        stream_hashes, stream_details, streams_by_kind = analyze_pdf_streams(pdf_bytes)
        layers["stream_hashes"] = stream_hashes
        layers["stream_details"] = stream_details
        layers["streams_by_kind"] = streams_by_kind
        layers["generator_fingerprint"] = generator_fingerprint(streams_by_kind)
        for key, value in layers.items():
            setattr(result, key, value)
    except Exception as exc:
        result.extraction_error = str(exc)

    return result


def _normalize(value: Any) -> Optional[str]:
    if value is None:
        return None
    text = str(value).strip()
    return text or None


def _extract_text(pdf: pdfplumber.PDF) -> str:
    parts: List[str] = []
    try:
        for page in pdf.pages:
            page_text = page.extract_text() or ""
            if page_text.strip():
                parts.append(page_text)
    finally:
        pdf.close()
    return "\n".join(parts)


def _detect_javascript(reader: PdfReader) -> bool:
    try:
        root = reader.trailer.get("/Root", {})
        if hasattr(root, "get_object"):
            root = root.get_object()
        names = root.get("/Names") if isinstance(root, dict) else None
        if names and hasattr(names, "get_object"):
            names = names.get_object()
        if isinstance(names, dict) and names.get("/JavaScript"):
            return True

        for page in reader.pages:
            page_obj = page.get_object() if hasattr(page, "get_object") else page
            if isinstance(page_obj, dict):
                annots = page_obj.get("/Annots")
                if annots:
                    return True
    except Exception:
        return False
    return False


def _detect_forms(reader: PdfReader) -> bool:
    try:
        root = reader.trailer.get("/Root", {})
        if hasattr(root, "get_object"):
            root = root.get_object()
        if isinstance(root, dict) and root.get("/AcroForm"):
            return True
    except Exception:
        return False
    return False


def _detect_attachments(reader: PdfReader) -> bool:
    try:
        root = reader.trailer.get("/Root", {})
        if hasattr(root, "get_object"):
            root = root.get_object()
        names = root.get("/Names") if isinstance(root, dict) else None
        if names and hasattr(names, "get_object"):
            names = names.get_object()
        if isinstance(names, dict) and names.get("/EmbeddedFiles"):
            return True
    except Exception:
        return False
    return False


def _extract_fonts(reader: PdfReader) -> List[str]:
    fonts: set[str] = set()
    try:
        for page in reader.pages:
            page_obj = page.get_object() if hasattr(page, "get_object") else page
            if not isinstance(page_obj, dict):
                continue
            resources = page_obj.get("/Resources")
            if resources and hasattr(resources, "get_object"):
                resources = resources.get_object()
            if not isinstance(resources, dict):
                continue
            font_dict = resources.get("/Font")
            if font_dict and hasattr(font_dict, "get_object"):
                font_dict = font_dict.get_object()
            if isinstance(font_dict, dict):
                for name in font_dict.keys():
                    fonts.add(str(name).lstrip("/"))
    except Exception:
        pass
    return sorted(fonts)


def _detect_image_only(pdf_bytes: bytes, text_extractable: bool) -> bool:
    if text_extractable:
        return False
    try:
        doc = fitz.open(stream=pdf_bytes, filetype="pdf")
        has_images = False
        for page in doc:
            if page.get_images():
                has_images = True
                break
        doc.close()
        return has_images
    except Exception:
        return False


def match_suspicious_producers(*values: Optional[str]) -> List[str]:
    matched: List[str] = []
    for value in values:
        if not value:
            continue
        value_lower = value.lower()
        for name in SUSPICIOUS_PRODUCERS:
            if name in value_lower and name not in matched:
                matched.append(name)
    return matched


def parse_merchant_name(text: str) -> Optional[str]:
    patterns = [
        r"(?:наименование|магазин|продавец|получатель|мерчант)[:\s\n]+([^\n]{3,120})",
        r"(?:merchant|store)[:\s]+([^\n]{3,120})",
    ]
    for pattern in patterns:
        match = re.search(pattern, text, re.IGNORECASE)
        if match:
            return match.group(1).strip()
    return None


def parse_amount(text: str) -> Optional[str]:
    patterns = [
        r"(?:сумма|amount|итого)[:\s]*([0-9\s]+[.,][0-9]{2})\s*(?:₽|руб\.?|rub)?",
        r"([0-9\s]+[.,][0-9]{2})\s*(?:₽|руб\.?|rub)",
    ]
    for pattern in patterns:
        match = re.search(pattern, text, re.IGNORECASE)
        if match:
            return re.sub(r"\s+", "", match.group(1)).replace(",", ".")
    return None


def parse_date(text: str) -> Optional[str]:
    patterns = [
        r"(\d{2}[./]\d{2}[./]\d{4})",
        r"(\d{4}-\d{2}-\d{2})",
        r"(\d{2}\s+(?:январ|феврал|март|апрел|ма[йя]|июн|июл|август|сентябр|октябр|ноябр|декабр)\w*\s+\d{4})",
    ]
    for pattern in patterns:
        match = re.search(pattern, text, re.IGNORECASE)
        if match:
            return match.group(1)
    return None


def parse_receipt_number(text: str) -> Optional[str]:
    patterns = [
        r"Номер операции в СБП\s*\n?\s*([A-Za-z0-9]+)",
        r"Номер документа\s*\n?\s*([0-9]{10,})",
        r"(?:номер|чек|rrn|id|операци)[:\s#№]*([A-Za-z0-9-]{6,})",
        r"(?:receipt|transaction)[:\s#]*([A-Za-z0-9-]{6,})",
    ]
    for pattern in patterns:
        match = re.search(pattern, text, re.IGNORECASE)
        if match:
            return match.group(1)
    return None
