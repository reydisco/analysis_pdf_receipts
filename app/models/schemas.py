from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field


class AnalysisStatus(str, Enum):
    PENDING = "pending"
    COMPLETED = "completed"
    FAILED = "failed"


class Verdict(str, Enum):
    ORIGINAL = "original"
    SUSPICIOUS = "suspicious"
    FAKE = "fake"
    UNKNOWN = "unknown"


class CheckResult(BaseModel):
    name: str
    passed: bool
    weight: float
    details: str


class ImageSign(BaseModel):
    xref: int
    ext: str
    width: int
    height: int
    xres: Optional[int] = None
    yres: Optional[int] = None
    pixel_md5: str


class TechnicalSigns(BaseModel):
    pdf_version: Optional[str] = None
    producer: Optional[str] = None
    creator: Optional[str] = None
    author: Optional[str] = None
    creation_date: Optional[str] = None
    mod_date: Optional[str] = None
    page_count: int = 0
    encrypted: bool = False
    has_javascript: bool = False
    has_forms: bool = False
    has_attachments: bool = False
    embedded_fonts: List[str] = Field(default_factory=list)
    text_extractable: bool = False
    image_only: bool = False
    ocr_used: bool = False
    suspicious_producers: List[str] = Field(default_factory=list)
    has_valid_header: bool = False
    has_xref: bool = False
    has_trailer: bool = False
    has_eof: bool = False
    eof_count: int = 0
    object_count: int = 0
    xref_length: int = 0
    is_repaired: bool = False
    md5: Optional[str] = None
    sha256: Optional[str] = None
    base_fonts: List[str] = Field(default_factory=list)
    font_count: int = 0
    font_types: List[str] = Field(default_factory=list)
    max_image_dpi: int = 0
    image_count: int = 0
    images: List[ImageSign] = Field(default_factory=list)
    image_hashes: List[str] = Field(default_factory=list)
    content_skeleton_md5: Optional[str] = None
    tm_y_count: int = 0
    tm_positions: List[List[float]] = Field(default_factory=list)
    date_line_tm_x: Optional[float] = None
    date_line_tm_y: Optional[float] = None
    stream_hashes: Dict[str, str] = Field(default_factory=dict)
    stream_details: List[Dict[str, Any]] = Field(default_factory=list)
    streams_by_kind: Dict[str, List[str]] = Field(default_factory=dict)
    generator_fingerprint: Optional[str] = None
    meta_text_delta_sec: Optional[float] = None
    has_digital_signature: bool = False


class ContentSigns(BaseModel):
    bank_detected: Optional[str] = None
    amount_found: Optional[str] = None
    date_found: Optional[str] = None
    receipt_number_found: Optional[str] = None
    status_found: Optional[str] = None
    required_fields_present: bool = False
    has_phone_field: bool = False
    has_inn: bool = False
    inn_found: Optional[str] = None
    inn_valid: Optional[bool] = None
    merchant_name: Optional[str] = None


class FileAnalysisResult(BaseModel):
    filename: str
    verdict: Verdict
    confidence: float
    reasons: List[str] = Field(default_factory=list)
    technical_signs: TechnicalSigns
    content_signs: ContentSigns
    checks: List[CheckResult] = Field(default_factory=list)
    error: Optional[str] = None


class CheckReceiptResponse(BaseModel):
    analysis_id: str
    status: AnalysisStatus
    files: List[str]


class AnalysisReport(BaseModel):
    analysis_id: str
    status: AnalysisStatus
    created_at: datetime
    files: List[FileAnalysisResult]
    error: Optional[str] = None


class ErrorResponse(BaseModel):
    detail: str


class PdfExtractResult(BaseModel):
    metadata: Dict[str, Any] = Field(default_factory=dict)
    text: str = ""
    page_count: int = 0
    pdf_version: Optional[str] = None
    encrypted: bool = False
    has_javascript: bool = False
    has_forms: bool = False
    has_attachments: bool = False
    embedded_fonts: List[str] = Field(default_factory=list)
    image_only: bool = False
    text_extractable: bool = False
    ocr_used: bool = False
    extraction_error: Optional[str] = None
    has_valid_header: bool = False
    has_xref: bool = False
    has_trailer: bool = False
    has_eof: bool = False
    eof_count: int = 0
    object_count: int = 0
    xref_length: int = 0
    is_repaired: bool = False
    md5: Optional[str] = None
    sha256: Optional[str] = None
    base_fonts: List[str] = Field(default_factory=list)
    font_count: int = 0
    font_details: List[Dict[str, Any]] = Field(default_factory=list)
    font_types: List[str] = Field(default_factory=list)
    max_image_dpi: int = 0
    images: List[Dict[str, Any]] = Field(default_factory=list)
    image_count: int = 0
    image_hashes: List[str] = Field(default_factory=list)
    content_skeleton_md5: Optional[str] = None
    tm_y_count: int = 0
    tm_y_grid: List[float] = Field(default_factory=list)
    tm_positions: List[List[float]] = Field(default_factory=list)
    date_line_tm_x: Optional[float] = None
    date_line_tm_y: Optional[float] = None
    stream_hashes: Dict[str, str] = Field(default_factory=dict)
    stream_details: List[Dict[str, Any]] = Field(default_factory=list)
    streams_by_kind: Dict[str, List[str]] = Field(default_factory=dict)
    generator_fingerprint: Optional[str] = None
    meta_text_delta_sec: Optional[float] = None
    has_digital_signature: bool = False

    model_config = {"arbitrary_types_allowed": True}
