import re
from typing import Dict, List, Optional, Tuple

from app.models.schemas import (
    ContentSigns,
    FileAnalysisResult,
    ImageSign,
    TechnicalSigns,
    Verdict,
)
from app.services.checks import build_checks, detect_bank, load_reference_profiles
from app.services.inn_utils import analyze_inns
from app.services.pdf_extractor import (
    extract_pdf,
    match_suspicious_producers,
    parse_amount,
    parse_date,
    parse_merchant_name,
    parse_receipt_number,
)
from app.services.verdict import calculate_verdict


class ReceiptAnalyzer:
    def analyze_file(
        self,
        filename: str,
        pdf_bytes: bytes,
        batch_fingerprint: Optional[str] = None,
        batch_duplicates: Optional[List[str]] = None,
    ) -> FileAnalysisResult:
        extracted = extract_pdf(pdf_bytes)

        if extracted.extraction_error:
            return FileAnalysisResult(
                filename=filename,
                verdict=Verdict.UNKNOWN,
                confidence=0.0,
                reasons=[f"Ошибка извлечения PDF: {extracted.extraction_error}"],
                technical_signs=TechnicalSigns(),
                content_signs=ContentSigns(),
                checks=[],
                error=extracted.extraction_error,
            )

        text_lower = extracted.text.lower()
        profiles = load_reference_profiles()
        bank_profile = detect_bank(text_lower, profiles)
        checks = [
            check.run(extracted, text_lower)
            for check in build_checks(bank_profile, batch_fingerprint, batch_duplicates)
        ]
        verdict, confidence, reasons = calculate_verdict(checks)

        amount = parse_amount(extracted.text)
        date = parse_date(extracted.text)
        receipt_number = parse_receipt_number(extracted.text)
        status_found = None
        if bank_profile:
            for keyword in bank_profile.get("status_keywords", []):
                if keyword in text_lower:
                    status_found = keyword
                    break

        has_phone = (
            "телефон получателя" in text_lower
            or "номер телефона получателя" in text_lower
        )
        inn_found, has_inn, inn_valid = analyze_inns(extracted.text)
        merchant_name = parse_merchant_name(extracted.text)

        required_fields_present = all(
            [
                bool(amount),
                bool(date) or bool(re.search(r"\d{1,2}\s+[а-яё]+\s+\d{4}", text_lower)),
                bool(status_found),
            ]
        ) if bank_profile else False

        producer = extracted.metadata.get("producer")
        creator = extracted.metadata.get("creator")
        images = [
            ImageSign(
                xref=img["xref"],
                ext=img["ext"],
                width=img["width"],
                height=img["height"],
                xres=img.get("xres"),
                yres=img.get("yres"),
                pixel_md5=img["pixel_md5"],
            )
            for img in extracted.images
        ]

        technical_signs = TechnicalSigns(
            pdf_version=extracted.pdf_version,
            producer=producer,
            creator=extracted.metadata.get("creator"),
            author=extracted.metadata.get("author"),
            creation_date=extracted.metadata.get("creation_date"),
            mod_date=extracted.metadata.get("mod_date"),
            page_count=extracted.page_count,
            encrypted=extracted.encrypted,
            has_javascript=extracted.has_javascript,
            has_forms=extracted.has_forms,
            has_attachments=extracted.has_attachments,
            embedded_fonts=extracted.embedded_fonts,
            text_extractable=extracted.text_extractable,
            image_only=extracted.image_only,
            ocr_used=extracted.ocr_used,
            suspicious_producers=match_suspicious_producers(producer, creator),
            has_valid_header=extracted.has_valid_header,
            has_xref=extracted.has_xref,
            has_trailer=extracted.has_trailer,
            has_eof=extracted.has_eof,
            eof_count=extracted.eof_count,
            object_count=extracted.object_count,
            xref_length=extracted.xref_length,
            is_repaired=extracted.is_repaired,
            md5=extracted.md5,
            sha256=extracted.sha256,
            base_fonts=extracted.base_fonts,
            font_count=extracted.font_count,
            font_types=extracted.font_types,
            max_image_dpi=extracted.max_image_dpi,
            image_count=extracted.image_count,
            images=images,
            image_hashes=extracted.image_hashes,
            content_skeleton_md5=extracted.content_skeleton_md5,
            tm_y_count=extracted.tm_y_count,
            tm_positions=extracted.tm_positions,
            date_line_tm_x=extracted.date_line_tm_x,
            date_line_tm_y=extracted.date_line_tm_y,
            stream_hashes=extracted.stream_hashes,
            stream_details=extracted.stream_details,
            generator_fingerprint=extracted.generator_fingerprint,
            meta_text_delta_sec=extracted.meta_text_delta_sec,
            has_digital_signature=extracted.has_digital_signature,
        )

        content_signs = ContentSigns(
            bank_detected=bank_profile["bank_id"] if bank_profile else None,
            amount_found=amount,
            date_found=date,
            receipt_number_found=receipt_number,
            status_found=status_found,
            required_fields_present=required_fields_present,
            has_phone_field=has_phone,
            has_inn=has_inn,
            inn_found=inn_found,
            inn_valid=inn_valid if has_inn else None,
            merchant_name=merchant_name,
        )

        return FileAnalysisResult(
            filename=filename,
            verdict=verdict,
            confidence=confidence,
            reasons=reasons,
            technical_signs=technical_signs,
            content_signs=content_signs,
            checks=checks,
        )

    def analyze_files(self, files: List[Tuple[str, bytes]]) -> List[FileAnalysisResult]:
        extracted_list = []
        for filename, content in files:
            extracted = extract_pdf(content)
            extracted_list.append((filename, content, extracted))

        md5_map: Dict[str, List[str]] = {}
        struct_map: Dict[str, List[str]] = {}
        for filename, _, extracted in extracted_list:
            if extracted.md5:
                md5_map.setdefault(extracted.md5, []).append(filename)
            struct_key = self._structural_fingerprint(extracted)
            if struct_key:
                struct_map.setdefault(struct_key, []).append(filename)

        results: List[FileAnalysisResult] = []
        for filename, content, extracted in extracted_list:
            duplicates = [
                name for name in md5_map.get(extracted.md5 or "", []) if name != filename
            ]
            struct_key = self._structural_fingerprint(extracted)
            struct_peers = struct_map.get(struct_key or "", [])
            batch_clone = struct_key and len(struct_peers) > 1 and filename in struct_peers
            if extracted.extraction_error:
                results.append(self.analyze_file(filename, content))
                continue
            results.append(
                self.analyze_file(
                    filename,
                    content,
                    batch_fingerprint=struct_key if batch_clone else None,
                    batch_duplicates=duplicates,
                )
            )
        return results

    def _structural_fingerprint(self, extracted) -> Optional[str]:
        if not extracted.content_skeleton_md5 or not extracted.image_hashes:
            return None
        images = ",".join(extracted.image_hashes)
        return f"{extracted.content_skeleton_md5}:{images}"
