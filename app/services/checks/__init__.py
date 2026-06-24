import json
import re
from pathlib import Path
from typing import Dict, List, Optional

from app.config import MAX_IMAGE_DPI, MODDATE_LATER_THRESHOLD_SEC, REFERENCE_PROFILES_FILE
from app.models.schemas import CheckResult, PdfExtractResult
from app.services.checks.base import BaseCheck
from app.services.inn_utils import analyze_inns
from app.services.layer_extractor import date_line_tm_at_y, parse_pdf_meta_date
from app.services.pdf_extractor import match_suspicious_producers, parse_amount, parse_date
from app.services.reference_fingerprints import compare_generator_streams, merge_profile_fingerprints
from app.services.stream_analyzer import generator_fingerprint

UNUSUAL_FONT_SUBSTRINGS = [
    "comic",
    "impact",
    "papyrus",
    "courier new",
    "times new roman",
    "calibri",
]


class MetadataProducerCheck(BaseCheck):
    name = "metadata_producer"
    weight = 0.15

    def run(self, extracted: PdfExtractResult, text_lower: str) -> CheckResult:
        producer = extracted.metadata.get("producer")
        creator = extracted.metadata.get("creator")
        suspicious = match_suspicious_producers(producer, creator)
        if suspicious:
            source = producer or creator
            return CheckResult(
                name=self.name,
                passed=False,
                weight=self.weight,
                details=f"Producer/Creator '{source}' характерен для печати/редактирования: {', '.join(suspicious)}",
            )
        if not producer and not creator:
            return CheckResult(
                name=self.name,
                passed=False,
                weight=self.weight * 0.5,
                details="Producer и Creator отсутствуют в метаданных PDF",
            )
        return CheckResult(
            name=self.name,
            passed=True,
            weight=self.weight,
            details=f"Producer: {producer or '—'}, Creator: {creator or '—'}",
        )


class MetadataDateConsistencyCheck(BaseCheck):
    name = "metadata_date_consistency"
    weight = 0.1

    def run(self, extracted: PdfExtractResult, text_lower: str) -> CheckResult:
        creation = extracted.metadata.get("creation_date")
        mod_date = extracted.metadata.get("mod_date")
        if not creation or not mod_date:
            return CheckResult(
                name=self.name,
                passed=True,
                weight=self.weight,
                details="CreationDate и ModDate согласованы или отсутствуют",
            )
        if creation == mod_date:
            return CheckResult(
                name=self.name,
                passed=True,
                weight=self.weight,
                details="CreationDate и ModDate совпадают",
            )

        creation_dt = parse_pdf_meta_date(creation)
        mod_dt = parse_pdf_meta_date(mod_date)
        if creation_dt and mod_dt:
            delta = (mod_dt - creation_dt).total_seconds()
            if delta > MODDATE_LATER_THRESHOLD_SEC:
                hours = int(delta // 3600)
                return CheckResult(
                    name=self.name,
                    passed=False,
                    weight=self.weight,
                    details=f"ModDate более чем на {hours} ч позже CreationDate — документ мог быть изменён",
                )
            if delta > 0:
                return CheckResult(
                    name=self.name,
                    passed=False,
                    weight=self.weight * 0.6,
                    details="CreationDate и ModDate различаются — документ мог быть изменён после создания",
                )

        return CheckResult(
            name=self.name,
            passed=False,
            weight=self.weight * 0.6,
            details="CreationDate и ModDate различаются — документ мог быть изменён после создания",
        )


class StructurePdfVersionCheck(BaseCheck):
    name = "structure_pdf_version"
    weight = 0.05

    def __init__(self, bank_profile: Optional[Dict]) -> None:
        self.bank_profile = bank_profile

    def run(self, extracted: PdfExtractResult, text_lower: str) -> CheckResult:
        version = extracted.pdf_version
        if not version:
            return CheckResult(
                name=self.name,
                passed=False,
                weight=self.weight * 0.5,
                details="Версия PDF не определена",
            )

        expected = (self.bank_profile or {}).get(
            "expected_pdf_versions", ["1.4", "1.5", "1.6", "1.7"]
        )
        if version in expected or any(version.startswith(item) for item in expected):
            return CheckResult(
                name=self.name,
                passed=True,
                weight=self.weight,
                details=f"Версия PDF {version} в допустимом диапазоне",
            )
        return CheckResult(
            name=self.name,
            passed=False,
            weight=self.weight,
            details=f"Версия PDF {version} не типична для банковских чеков (ожидалось {expected})",
        )


class StructurePdfIntegrityCheck(BaseCheck):
    name = "structure_pdf_integrity"
    weight = 0.15

    def run(self, extracted: PdfExtractResult, text_lower: str) -> CheckResult:
        issues: List[str] = []
        if not extracted.has_valid_header:
            issues.append("нет заголовка %PDF")
        if not extracted.has_xref:
            issues.append("нет xref")
        if not extracted.has_trailer:
            issues.append("нет trailer")
        if not extracted.has_eof:
            issues.append("нет %%EOF")
        if extracted.eof_count > 1:
            issues.append(f"несколько ревизий (%%EOF={extracted.eof_count})")
        if extracted.is_repaired:
            issues.append("PDF восстановлен (repaired)")
        if extracted.object_count > 500:
            issues.append(f"слишком много объектов ({extracted.object_count})")
        if extracted.object_count < 5:
            issues.append(f"слишком мало объектов ({extracted.object_count})")

        if issues:
            return CheckResult(
                name=self.name,
                passed=False,
                weight=self.weight,
                details="; ".join(issues),
            )
        return CheckResult(
            name=self.name,
            passed=True,
            weight=self.weight,
            details=(
                f"Структура PDF корректна: obj={extracted.object_count}, "
                f"xref={extracted.xref_length}, eof={extracted.eof_count}"
            ),
        )


class StructureImageOnlyCheck(BaseCheck):
    name = "structure_image_only"
    weight = 0.15

    def run(self, extracted: PdfExtractResult, text_lower: str) -> CheckResult:
        if extracted.image_only and not extracted.text_extractable:
            return CheckResult(
                name=self.name,
                passed=False,
                weight=self.weight,
                details="PDF содержит изображение без извлекаемого текстового слоя",
            )
        if not extracted.text_extractable:
            return CheckResult(
                name=self.name,
                passed=False,
                weight=self.weight * 0.7,
                details="Текст из PDF извлечь не удалось или он слишком короткий",
            )
        if extracted.ocr_used:
            return CheckResult(
                name=self.name,
                passed=True,
                weight=self.weight * 0.8,
                details="Текстовый слой отсутствовал — текст получен через OCR",
            )
        return CheckResult(
            name=self.name,
            passed=True,
            weight=self.weight,
            details="Текстовый слой присутствует",
        )


class StructureSecurityCheck(BaseCheck):
    name = "structure_security"
    weight = 0.1

    def run(self, extracted: PdfExtractResult, text_lower: str) -> CheckResult:
        issues: List[str] = []
        if extracted.has_javascript:
            issues.append("JavaScript")
        if extracted.has_forms:
            issues.append("формы")
        if extracted.has_attachments:
            issues.append("вложения")
        if extracted.encrypted:
            issues.append("шифрование")
        if issues:
            return CheckResult(
                name=self.name,
                passed=False,
                weight=self.weight,
                details=f"Нестандартные элементы: {', '.join(issues)}",
            )
        return CheckResult(
            name=self.name,
            passed=True,
            weight=self.weight,
            details="Подозрительные структурные элементы не обнаружены",
        )


class StructureFontsCheck(BaseCheck):
    name = "structure_fonts"
    weight = 0.1

    def __init__(self, bank_profile: Optional[Dict]) -> None:
        self.bank_profile = bank_profile

    def run(self, extracted: PdfExtractResult, text_lower: str) -> CheckResult:
        if extracted.font_count == 0:
            return CheckResult(
                name=self.name,
                passed=False,
                weight=self.weight * 0.5,
                details="Шрифты не обнаружены",
            )

        max_fonts = 8
        if self.bank_profile:
            max_fonts = self.bank_profile.get("max_font_count", 8)

        if extracted.font_count > max_fonts:
            return CheckResult(
                name=self.name,
                passed=False,
                weight=self.weight,
                details=f"Слишком много шрифтов: {extracted.font_count} (лимит {max_fonts})",
            )

        unusual = [
            font
            for font in extracted.base_fonts
            if any(item in font.lower() for item in UNUSUAL_FONT_SUBSTRINGS)
        ]
        if unusual:
            return CheckResult(
                name=self.name,
                passed=False,
                weight=self.weight * 0.7,
                details=f"Нетипичные шрифты для чека: {unusual}",
            )

        expected_types = (self.bank_profile or {}).get("expected_font_types", [])
        if expected_types and extracted.font_types:
            if not any(font_type in expected_types for font_type in extracted.font_types):
                return CheckResult(
                    name=self.name,
                    passed=False,
                    weight=self.weight * 0.5,
                    details=f"Типы шрифтов {extracted.font_types} не соответствуют ожидаемым {expected_types}",
                )

        expected_substr = self.bank_profile.get("expected_font_substr") if self.bank_profile else None
        if expected_substr:
            has_expected = any(
                expected_substr.lower() in font.lower() for font in extracted.base_fonts
            )
            if not has_expected:
                return CheckResult(
                    name=self.name,
                    passed=False,
                    weight=self.weight * 0.6,
                    details=f"Ожидался шрифт с '{expected_substr}', найдено: {extracted.base_fonts}",
                )

        return CheckResult(
            name=self.name,
            passed=True,
            weight=self.weight,
            details=(
                f"Шрифты: {extracted.base_fonts} "
                f"(count={extracted.font_count}, types={extracted.font_types})"
            ),
        )


class StructureImagesCheck(BaseCheck):
    name = "structure_images"
    weight = 0.15

    def __init__(self, bank_profile: Optional[Dict]) -> None:
        self.bank_profile = bank_profile

    def run(self, extracted: PdfExtractResult, text_lower: str) -> CheckResult:
        if extracted.image_count == 0:
            return CheckResult(
                name=self.name,
                passed=False,
                weight=self.weight * 0.5,
                details="Изображения не обнаружены",
            )

        if extracted.image_only and not extracted.text_extractable:
            return CheckResult(
                name=self.name,
                passed=False,
                weight=self.weight,
                details="Страница состоит только из изображения",
            )

        max_dpi = extracted.max_image_dpi
        if max_dpi > MAX_IMAGE_DPI:
            return CheckResult(
                name=self.name,
                passed=False,
                weight=self.weight * 0.7,
                details=f"Высокое разрешение изображения ({max_dpi} dpi) — возможен скан вместо нативного PDF",
            )

        expected = (self.bank_profile or {}).get("expected_image_hashes", [])
        skeleton = extracted.content_skeleton_md5
        skeleton_images = (self.bank_profile or {}).get("skeleton_image_fingerprints", {})
        if skeleton and skeleton in skeleton_images:
            expected = skeleton_images[skeleton]

        if expected and extracted.image_hashes:
            def matches(h: str) -> bool:
                return any(h == e or h.startswith(e) or e.startswith(h) for e in expected)

            matched = sum(1 for h in extracted.image_hashes if matches(h))
            if matched == 0:
                return CheckResult(
                    name=self.name,
                    passed=False,
                    weight=self.weight,
                    details="Хеши изображений не совпадают с эталонным профилем банка",
                )
            if matched < len(expected):
                return CheckResult(
                    name=self.name,
                    passed=False,
                    weight=self.weight * 0.6,
                    details=f"Совпало {matched}/{len(expected)} эталонных изображений",
                )
            return CheckResult(
                name=self.name,
                passed=True,
                weight=self.weight,
                details=f"Изображения совпадают с эталоном ({matched}/{len(expected)})",
            )

        return CheckResult(
            name=self.name,
            passed=True,
            weight=self.weight,
            details=f"Изображений: {extracted.image_count}, max_dpi={max_dpi or '—'}",
        )


class StructureLayoutCheck(BaseCheck):
    name = "structure_layout"
    weight = 0.2

    def __init__(self, bank_profile: Optional[Dict]) -> None:
        self.bank_profile = bank_profile

    def run(self, extracted: PdfExtractResult, text_lower: str) -> CheckResult:
        if not self.bank_profile:
            return CheckResult(
                name=self.name,
                passed=False,
                weight=self.weight * 0.3,
                details="Банк не определён — проверка layout невозможна",
            )

        expected_skeletons = self.bank_profile.get("expected_content_skeleton_md5", [])
        if expected_skeletons and extracted.content_skeleton_md5:
            if extracted.content_skeleton_md5 not in expected_skeletons:
                return CheckResult(
                    name=self.name,
                    passed=False,
                    weight=self.weight,
                    details=(
                        f"Skeleton content stream '{extracted.content_skeleton_md5}' "
                        f"не совпадает с эталонными вариантами шаблона"
                    ),
                )

        expected_y_counts = self.bank_profile.get("expected_tm_y_counts", [])
        if expected_y_counts and extracted.tm_y_count not in expected_y_counts:
            return CheckResult(
                name=self.name,
                passed=False,
                weight=self.weight * 0.7,
                details=(
                    f"Сетка вёрстки Tm_y={extracted.tm_y_count} "
                    f"не соответствует эталону {expected_y_counts}"
                ),
            )

        return CheckResult(
            name=self.name,
            passed=True,
            weight=self.weight,
            details=(
                f"Layout: skeleton={extracted.content_skeleton_md5}, "
                f"Tm_y={extracted.tm_y_count}"
            ),
        )


class StructureDateTmCheck(BaseCheck):
    name = "structure_date_tm"
    weight = 0.12

    def __init__(self, bank_profile: Optional[Dict]) -> None:
        self.bank_profile = bank_profile

    def run(self, extracted: PdfExtractResult, text_lower: str) -> CheckResult:
        if not self.bank_profile:
            return CheckResult(
                name=self.name,
                passed=True,
                weight=self.weight * 0.3,
                details="Банк не определён — проверка Tm строки даты пропущена",
            )

        skeleton = extracted.content_skeleton_md5
        expected_map = self.bank_profile.get("expected_date_tm_by_skeleton") or {}
        if not skeleton or skeleton not in expected_map:
            return CheckResult(
                name=self.name,
                passed=True,
                weight=self.weight * 0.3,
                details="Эталон Tm строки даты не задан для данного skeleton",
            )

        spec = expected_map[skeleton]
        expected_x = float(spec["x"])
        expected_y = float(spec["y"])
        tolerance_x = float(spec.get("tolerance_x", 1.0))
        tolerance_y = float(spec.get("tolerance_y", 0.5))

        positions = extracted.tm_positions
        if not positions:
            return CheckResult(
                name=self.name,
                passed=False,
                weight=self.weight,
                details="Координаты Tm в content stream не извлечены",
            )

        date_tm = date_line_tm_at_y(positions, expected_y, tolerance_y)
        if not date_tm:
            return CheckResult(
                name=self.name,
                passed=False,
                weight=self.weight * 0.7,
                details=f"Tm строки даты не найден (ожидался Y≈{expected_y})",
            )

        delta_x = abs(date_tm[0] - expected_x)
        known_samples = set(self.bank_profile.get("known_sample_file_md5") or [])
        file_md5 = extracted.md5 or ""

        if delta_x <= tolerance_x and file_md5 not in known_samples:
            return CheckResult(
                name=self.name,
                passed=False,
                weight=self.weight,
                details=(
                    f"Tm строки даты X={date_tm[0]} Y={date_tm[1]} совпадает с эталонным бланком, "
                    f"но MD5 файла не среди известных оригиналов — подозрительное заполнение шаблона"
                ),
            )

        return CheckResult(
            name=self.name,
            passed=True,
            weight=self.weight,
            details=(
                f"Tm строки даты X={date_tm[0]} Y={date_tm[1]} "
                f"(эталон X={expected_x}, ΔX={delta_x:.2f}pt)"
            ),
        )


class ContentRequiredFieldsCheck(BaseCheck):
    name = "content_required_fields"
    weight = 0.2

    def __init__(self, bank_profile: Optional[Dict]) -> None:
        self.bank_profile = bank_profile

    def run(self, extracted: PdfExtractResult, text_lower: str) -> CheckResult:
        if not self.bank_profile:
            return CheckResult(
                name=self.name,
                passed=False,
                weight=self.weight * 0.4,
                details="Банк не определён — невозможно проверить обязательные поля",
            )

        missing: List[str] = []
        if not parse_amount(extracted.text):
            missing.append("сумма")
        if not parse_date(extracted.text) and not self._has_textual_date(text_lower):
            missing.append("дата")
        if not any(k in text_lower for k in self.bank_profile.get("status_keywords", [])):
            missing.append("статус")

        if missing:
            return CheckResult(
                name=self.name,
                passed=False,
                weight=self.weight,
                details=f"Отсутствуют поля для {self.bank_profile['bank_name']}: {', '.join(missing)}",
            )
        return CheckResult(
            name=self.name,
            passed=True,
            weight=self.weight,
            details=f"Обязательные поля для {self.bank_profile['bank_name']} найдены",
        )

    def _has_textual_date(self, text_lower: str) -> bool:
        return bool(re.search(r"\d{1,2}\s+[а-яё]+\s+\d{4}", text_lower))


class ContentStatusCheck(BaseCheck):
    name = "content_status"
    weight = 0.05

    def __init__(self, bank_profile: Optional[Dict]) -> None:
        self.bank_profile = bank_profile

    def run(self, extracted: PdfExtractResult, text_lower: str) -> CheckResult:
        keywords = self.bank_profile.get("status_keywords", []) if self.bank_profile else [
            "успешно", "выполнено", "исполнено",
        ]
        if any(keyword in text_lower for keyword in keywords):
            return CheckResult(
                name=self.name,
                passed=True,
                weight=self.weight,
                details="Статус успешной операции найден",
            )
        return CheckResult(
            name=self.name,
            passed=False,
            weight=self.weight,
            details="Статус успешной операции не найден",
        )


class ContentInnCheck(BaseCheck):
    name = "content_inn"
    weight = 0.08

    def run(self, extracted: PdfExtractResult, text_lower: str) -> CheckResult:
        inn, found, valid = analyze_inns(extracted.text)
        if not found:
            return CheckResult(
                name=self.name,
                passed=True,
                weight=self.weight,
                details="ИНН в документе не найден",
            )
        if not valid:
            return CheckResult(
                name=self.name,
                passed=False,
                weight=self.weight,
                details=f"ИНН {inn} не прошёл проверку контрольной суммы",
            )
        return CheckResult(
            name=self.name,
            passed=True,
            weight=self.weight,
            details=f"ИНН {inn} валиден",
        )


class ContentMerchantCheck(BaseCheck):
    name = "content_merchant"
    weight = 0.08

    def __init__(self, bank_profile: Optional[Dict]) -> None:
        self.bank_profile = bank_profile

    def run(self, extracted: PdfExtractResult, text_lower: str) -> CheckResult:
        if self.bank_profile:
            bank_keywords = self.bank_profile.get("keywords", [])
            if any(keyword in text_lower for keyword in bank_keywords):
                return CheckResult(
                    name=self.name,
                    passed=True,
                    weight=self.weight,
                    details=f"Организация определена: {self.bank_profile['bank_name']}",
                )

        merchant_keywords = (
            self.bank_profile.get("merchant_keywords", []) if self.bank_profile else []
        ) or ["магазин", "продавец", "наименование", "получатель", "мерчант", "merchant"]
        if any(keyword in text_lower for keyword in merchant_keywords):
            return CheckResult(
                name=self.name,
                passed=True,
                weight=self.weight,
                details="Наименование организации/получателя найдено",
            )
        return CheckResult(
            name=self.name,
            passed=False,
            weight=self.weight * 0.6,
            details="Не найдено наименование организации, магазина или получателя",
        )


class StructureFileFingerprintCheck(BaseCheck):
    name = "structure_file_fingerprint"
    weight = 0.12

    def __init__(self, bank_profile: Optional[Dict]) -> None:
        self.bank_profile = bank_profile

    def run(self, extracted: PdfExtractResult, text_lower: str) -> CheckResult:
        fp = merge_profile_fingerprints(self.bank_profile)
        file_md5 = extracted.md5 or ""
        file_sha256 = extracted.sha256 or ""

        forbidden_md5 = set(fp.get("forbidden_file_md5") or [])
        forbidden_sha256 = set(fp.get("forbidden_file_sha256") or [])
        if file_md5 in forbidden_md5 or file_sha256 in forbidden_sha256:
            return CheckResult(
                name=self.name,
                passed=False,
                weight=self.weight,
                details=f"Файловый отпечаток совпадает с известной подделкой (md5={file_md5})",
            )

        expected_md5 = set((self.bank_profile or {}).get("known_sample_file_md5") or [])
        if expected_md5 and file_md5 in expected_md5:
            return CheckResult(
                name=self.name,
                passed=True,
                weight=self.weight,
                details=f"MD5 совпадает с известным образцом ({file_md5}); новые чеки с другими данными будут иметь другой MD5",
            )

        if self.bank_profile and (forbidden_md5 or forbidden_sha256):
            return CheckResult(
                name=self.name,
                passed=True,
                weight=self.weight,
                details=f"Файловый отпечаток не в blacklist (md5={file_md5})",
            )

        return CheckResult(
            name=self.name,
            passed=True,
            weight=self.weight * 0.5,
            details=f"Файловый отпечаток: md5={file_md5}",
        )


class StructureGeneratorCheck(BaseCheck):
    name = "structure_generator"
    weight = 0.15

    def __init__(self, bank_profile: Optional[Dict]) -> None:
        self.bank_profile = bank_profile

    def run(self, extracted: PdfExtractResult, text_lower: str) -> CheckResult:
        if not extracted.stream_hashes:
            return CheckResult(
                name=self.name,
                passed=False,
                weight=self.weight * 0.5,
                details="PDF-потоки не обнаружены",
            )

        fp = merge_profile_fingerprints(self.bank_profile)
        skeleton = extracted.content_skeleton_md5
        skeleton_images = fp.get("skeleton_image_stream_hashes") or {}
        required_images = list(fp.get("required_image_stream_hashes") or [])
        if skeleton and skeleton in skeleton_images:
            required_images = list(skeleton_images[skeleton])

        stream_details = extracted.stream_details or []
        missing_images, found_fake, generator_hashes = compare_generator_streams(
            extracted.stream_hashes,
            stream_details,
            required_images,
            fp.get("fake_generator_stream_hashes") or [],
        )

        if found_fake:
            kinds = []
            for item in stream_details:
                if item.get("md5") in found_fake:
                    kinds.append(item.get("kind", "?"))
            kind_hint = ", ".join(sorted(set(kinds))) or "content/font"
            return CheckResult(
                name=self.name,
                passed=False,
                weight=self.weight,
                details=(
                    "Тот же бланк (layout и image-потоки), но PDF собран другим генератором: "
                    f"обнаружены {kind_hint}-потоки известной подделки ({', '.join(found_fake[:3])}). "
                    "Сумма и ФИО могут отличаться у любого чека; здесь отличается упаковка "
                    "content/font-subset, а не только текст операции"
                ),
            )

        if missing_images and self.bank_profile:
            return CheckResult(
                name=self.name,
                passed=False,
                weight=self.weight * 0.7,
                details=(
                    f"Image-потоки шаблона не совпадают ({len(missing_images)} отсутствуют): "
                    f"{', '.join(missing_images[:3])}"
                ),
            )

        generator_count = len(generator_hashes)
        return CheckResult(
            name=self.name,
            passed=True,
            weight=self.weight,
            details=(
                f"Генератор PDF согласован с банковским шаблоном: image-потоки на месте, "
                f"{generator_count} content/font-поток(ов) не в blacklist фейка "
                f"(их hash меняется при другой сумме/ФИО — это нормально)"
            ),
        )


class StructureBatchCloneCheck(BaseCheck):
    name = "structure_batch_clone"
    weight = 0.1

    def __init__(self, batch_fingerprint: Optional[str] = None, batch_duplicates: Optional[List[str]] = None) -> None:
        self.batch_fingerprint = batch_fingerprint
        self.batch_duplicates = batch_duplicates or []

    def run(self, extracted: PdfExtractResult, text_lower: str) -> CheckResult:
        if self.batch_duplicates:
            return CheckResult(
                name=self.name,
                passed=False,
                weight=self.weight,
                details=f"Дубликат файла в пакете: {', '.join(self.batch_duplicates)}",
            )
        if self.batch_fingerprint:
            return CheckResult(
                name=self.name,
                passed=False,
                weight=self.weight * 0.8,
                details=(
                    f"Структурный клон в пакете (skeleton={extracted.content_skeleton_md5}, "
                    f"images={extracted.image_hashes[:2]})"
                ),
            )
        return CheckResult(
            name=self.name,
            passed=True,
            weight=self.weight,
            details="Структурных клонов в пакете не обнаружено",
        )


class ReferenceProfileCheck(BaseCheck):
    name = "reference_profile"
    weight = 0.15

    def __init__(self, bank_profile: Optional[Dict]) -> None:
        self.bank_profile = bank_profile

    def run(self, extracted: PdfExtractResult, text_lower: str) -> CheckResult:
        if not self.bank_profile:
            return CheckResult(
                name=self.name,
                passed=False,
                weight=self.weight * 0.3,
                details="Банк не определён — сравнение с эталоном невозможно",
            )

        producer = (extracted.metadata.get("producer") or "").lower()
        creator = (extracted.metadata.get("creator") or "").lower()
        forbidden = self.bank_profile.get("forbidden_producers", [])
        for item in forbidden:
            if item in producer or item in creator:
                source = producer or creator
                return CheckResult(
                    name=self.name,
                    passed=False,
                    weight=self.weight,
                    details=f"Producer/Creator не соответствует эталону {self.bank_profile['bank_name']}: {source}",
                )

        expected = self.bank_profile.get("expected_producers", [])
        if producer and not any(item in producer for item in expected):
            return CheckResult(
                name=self.name,
                passed=False,
                weight=self.weight * 0.6,
                details=f"Producer '{producer}' не совпадает с типичными для {self.bank_profile['bank_name']}",
            )

        return CheckResult(
            name=self.name,
            passed=True,
            weight=self.weight,
            details=f"Producer согласован с эталоном {self.bank_profile['bank_name']}",
        )


def load_reference_profiles() -> List[Dict]:
    if not REFERENCE_PROFILES_FILE.exists():
        return []
    with REFERENCE_PROFILES_FILE.open(encoding="utf-8") as file:
        return json.load(file)


def detect_bank(text_lower: str, profiles: List[Dict]) -> Optional[Dict]:
    for profile in profiles:
        keywords = profile.get("keywords", [])
        if any(keyword in text_lower for keyword in keywords):
            return profile
    return None


def build_checks(
    bank_profile: Optional[Dict],
    batch_fingerprint: Optional[str] = None,
    batch_duplicates: Optional[List[str]] = None,
) -> List[BaseCheck]:
    return [
        MetadataProducerCheck(),
        MetadataDateConsistencyCheck(),
        StructurePdfVersionCheck(bank_profile),
        StructurePdfIntegrityCheck(),
        StructureFileFingerprintCheck(bank_profile),
        StructureGeneratorCheck(bank_profile),
        StructureImageOnlyCheck(),
        StructureSecurityCheck(),
        StructureFontsCheck(bank_profile),
        StructureImagesCheck(bank_profile),
        StructureLayoutCheck(bank_profile),
        StructureDateTmCheck(bank_profile),
        StructureBatchCloneCheck(batch_fingerprint, batch_duplicates),
        ContentRequiredFieldsCheck(bank_profile),
        ContentStatusCheck(bank_profile),
        ContentInnCheck(),
        ContentMerchantCheck(bank_profile),
        ReferenceProfileCheck(bank_profile),
    ]
