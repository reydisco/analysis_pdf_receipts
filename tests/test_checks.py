import fitz
import pytest

from app.models.schemas import PdfExtractResult, Verdict
from app.services.analyzer import ReceiptAnalyzer
from app.services.checks import (
    ContentInnCheck,
    ContentMerchantCheck,
    ContentRequiredFieldsCheck,
    MetadataDateConsistencyCheck,
    MetadataProducerCheck,
    ReferenceProfileCheck,
    StructureFileFingerprintCheck,
    StructureImagesCheck,
    StructureLayoutCheck,
    StructureDateTmCheck,
    StructurePdfIntegrityCheck,
    StructurePdfVersionCheck,
    StructureGeneratorCheck,
    detect_bank,
    load_reference_profiles,
)
from app.services.inn_utils import analyze_inns, validate_inn
from app.services.pdf_extractor import extract_pdf, parse_amount, parse_date


def _make_pdf(text: str, producer=None):
    doc = fitz.open()
    page = doc.new_page()
    page.insert_text((72, 72), text, fontsize=12)
    if producer:
        doc.set_metadata({"producer": producer})
    pdf_bytes = doc.tobytes()
    doc.close()
    return pdf_bytes


def test_structure_file_fingerprint_flags_known_fake() -> None:
    profiles = load_reference_profiles()
    bank = profiles[0]
    extracted = PdfExtractResult(md5="4d2d2120d4fb4327ba49a462ddc680e6")
    result = StructureFileFingerprintCheck(bank).run(extracted, "сбербанк")
    assert result.passed is False


def test_structure_generator_flags_fake_generator_streams() -> None:
    profiles = load_reference_profiles()
    bank = profiles[0]
    extracted = PdfExtractResult(
        stream_hashes={
            "3": "ce77a308d3176350",
            "6": "128529ba4df92e87",
        },
        stream_details=[
            {"xref": 3, "kind": "image", "md5": "ce77a308d3176350", "size": 100},
            {"xref": 6, "kind": "content", "md5": "128529ba4df92e87", "size": 100},
        ],
        content_skeleton_md5="2610027195476775",
    )
    result = StructureGeneratorCheck(bank).run(extracted, "сбербанк")
    assert result.passed is False
    assert "генератором" in result.details.lower()


def test_structure_generator_allows_different_content_streams() -> None:
    profiles = load_reference_profiles()
    bank = profiles[0]
    extracted = PdfExtractResult(
        stream_hashes={
            "3": "ce77a308d3176350",
            "4": "28f96873e33aea75",
            "5": "1162f6ec1bd3f7e3",
            "6": "81936757541b2d8a",
            "9": "a8a7814af6974542",
            "12": "d6d506e257d75629",
        },
        stream_details=[
            {"xref": 3, "kind": "image", "md5": "ce77a308d3176350", "size": 1},
            {"xref": 4, "kind": "image", "md5": "28f96873e33aea75", "size": 1},
            {"xref": 5, "kind": "image", "md5": "1162f6ec1bd3f7e3", "size": 1},
            {"xref": 6, "kind": "content", "md5": "81936757541b2d8a", "size": 1},
            {"xref": 9, "kind": "font", "md5": "a8a7814af6974542", "size": 1},
            {"xref": 12, "kind": "cid_init", "md5": "d6d506e257d75629", "size": 1},
        ],
        content_skeleton_md5="2610027195476775",
    )
    result = StructureGeneratorCheck(bank).run(extracted, "сбербанк")
    assert result.passed is True
    assert "blacklist" in result.details.lower() or "нормально" in result.details.lower()


def test_analyzer_batch_marks_structural_clones() -> None:
    extracted = PdfExtractResult(
        md5="aaa",
        content_skeleton_md5="2610027195476775",
        image_hashes=["605162dac76c2a38b4d250ddd3546ff7"],
        stream_hashes={"3": "ce77a308d3176350", "6": "6f6c027af17f5ba7"},
        text="сбербанк перевод успешно сумма 100",
        text_extractable=True,
    )
    from app.services.checks import StructureBatchCloneCheck

    result = StructureBatchCloneCheck(batch_fingerprint="clone-key").run(extracted, extracted.text.lower())
    assert result.passed is False


def test_detect_bank_sberbank_sbp() -> None:
    profiles = load_reference_profiles()
    bank = detect_bank("чек по операции перевод по сбп", profiles)
    assert bank is not None
    assert bank["bank_id"] == "sberbank"


def test_structure_layout_check_passes_without_skeleton_profile() -> None:
    profiles = load_reference_profiles()
    bank = profiles[0]
    extracted = PdfExtractResult(
        content_skeleton_md5="35082afd224312b5",
        tm_y_count=24,
    )
    result = StructureLayoutCheck(bank).run(extracted, "перевод по сбп")
    assert result.passed is True


def test_detect_bank_sberbank() -> None:
    profiles = load_reference_profiles()
    bank = detect_bank("чек сбербанк перевод успешно", profiles)
    assert bank is not None
    assert bank["bank_id"] == "sberbank"


def test_metadata_producer_check_flags_suspicious() -> None:
    extracted = PdfExtractResult(
        metadata={"producer": "Microsoft Print To PDF"},
        text_extractable=True,
    )
    result = MetadataProducerCheck().run(extracted, "")
    assert result.passed is False


def test_metadata_producer_check_flags_word_creator() -> None:
    extracted = PdfExtractResult(
        metadata={"creator": "Microsoft Word"},
        text_extractable=True,
    )
    result = MetadataProducerCheck().run(extracted, "")
    assert result.passed is False


def test_metadata_date_consistency_moddate_later() -> None:
    extracted = PdfExtractResult(
        metadata={
            "creation_date": "D:20260620120000",
            "mod_date": "D:20260621130000",
        }
    )
    result = MetadataDateConsistencyCheck().run(extracted, "")
    assert result.passed is False
    assert "позже" in result.details.lower()


def test_reference_profile_check_matches_expected_producer() -> None:
    profiles = load_reference_profiles()
    bank = profiles[0]
    extracted = PdfExtractResult(metadata={"producer": "Sberbank iText"})
    result = ReferenceProfileCheck(bank).run(extracted, "сбербанк")
    assert result.passed is True


def test_content_required_fields_check_with_textual_date() -> None:
    profiles = load_reference_profiles()
    bank = profiles[0]
    text = "сбербанк\nСумма перевода\n6 670,00 ₽\n20 июня 2026\nстатус успешно"
    extracted = PdfExtractResult(text=text)
    result = ContentRequiredFieldsCheck(bank).run(extracted, text.lower())
    assert result.passed is True


def test_content_inn_check_valid() -> None:
    inn = "7707083893"
    assert validate_inn(inn) is True
    extracted = PdfExtractResult(text=f"ИНН {inn}")
    result = ContentInnCheck().run(extracted, extracted.text.lower())
    assert result.passed is True


def test_content_inn_check_invalid() -> None:
    extracted = PdfExtractResult(text="ИНН 1234567890")
    result = ContentInnCheck().run(extracted, extracted.text.lower())
    assert result.passed is False


def test_content_merchant_check_bank() -> None:
    profiles = load_reference_profiles()
    bank = profiles[0]
    extracted = PdfExtractResult(text="Чек Сбербанк перевод")
    result = ContentMerchantCheck(bank).run(extracted, extracted.text.lower())
    assert result.passed is True


def test_structure_pdf_version_check() -> None:
    profiles = load_reference_profiles()
    bank = profiles[0]
    extracted = PdfExtractResult(pdf_version="1.7")
    result = StructurePdfVersionCheck(bank).run(extracted, "")
    assert result.passed is True


def test_parse_amount_and_date() -> None:
    text = "Сумма: 1 500.00 ₽ Дата: 20.06.2026"
    assert parse_amount(text) == "1500.00"
    assert parse_date(text) == "20.06.2026"


def test_analyze_inns() -> None:
    inn, found, valid = analyze_inns("ИНН 7707083893")
    assert found is True
    assert valid is True
    assert inn == "7707083893"


def test_structure_pdf_integrity_on_valid_pdf() -> None:
    pdf_bytes = _make_pdf("Receipt test content with enough text for extraction", producer="TestProducer")
    extracted = extract_pdf(pdf_bytes)
    result = StructurePdfIntegrityCheck().run(extracted, "")
    assert result.passed is True
    assert extracted.sha256 is not None
    assert extracted.has_valid_header is True


def test_structure_images_check_without_profile_hashes() -> None:
    profiles = load_reference_profiles()
    bank = profiles[0]
    extracted = PdfExtractResult(
        image_count=3,
        image_hashes=[
            "605162dac76c2a38b4d250ddd3546ff7",
            "909a82a0f8a8cf209e04e9e79028e63c",
            "460d794cd1ab5be2b07f8779a5f24ce8",
        ],
    )
    result = StructureImagesCheck(bank).run(extracted, "")
    assert result.passed is True
    assert "Изображений: 3" in result.details


def test_structure_date_tm_check_skips_without_profile() -> None:
    profiles = load_reference_profiles()
    bank = profiles[0]
    extracted = PdfExtractResult(
        content_skeleton_md5="2610027195476775",
        tm_positions=[[71.77, 615.74]],
    )
    result = StructureDateTmCheck(bank).run(extracted, "сбербанк")
    assert result.passed is True
    assert "не задан" in result.details.lower()


def test_analyzer_passes_receipt_1() -> None:
    from pathlib import Path

    path = Path("receipt_1.pdf")
    if not path.exists():
        pytest.skip("receipt_1.pdf not in workspace")
    analyzer = ReceiptAnalyzer()
    result = analyzer.analyze_file("receipt_1.pdf", path.read_bytes())
    assert result.verdict.value == "original"


def test_analyzer_marks_receipt_2_suspicious() -> None:
    from pathlib import Path

    path = Path("receipt_2.pdf")
    if not path.exists():
        pytest.skip("receipt_2.pdf not in workspace")
    analyzer = ReceiptAnalyzer()
    result = analyzer.analyze_file("receipt_2.pdf", path.read_bytes())
    assert result.verdict.value == "suspicious"
    failed = {c.name for c in result.checks if not c.passed}
    assert "structure_file_fingerprint" in failed or "structure_generator" in failed


def test_analyzer_marks_suspicious_receipt() -> None:
    pdf_bytes = _make_pdf(
        "Сбербанк перевод\nСумма: 500.00 руб\nДата: 01.06.2026\nСтатус: успешно",
        producer="Microsoft Print To PDF",
    )
    analyzer = ReceiptAnalyzer()
    result = analyzer.analyze_file("receipt.pdf", pdf_bytes)
    assert result.verdict in (Verdict.SUSPICIOUS, Verdict.FAKE)
    assert result.technical_signs.producer == "Microsoft Print To PDF"


def test_analyzer_unknown_on_invalid_pdf() -> None:
    analyzer = ReceiptAnalyzer()
    result = analyzer.analyze_file("broken.pdf", b"not-a-pdf")
    assert result.verdict == Verdict.UNKNOWN
    assert result.error is not None


def test_extract_pdf_from_generated_file() -> None:
    pdf_bytes = _make_pdf("Receipt test content with enough text for extraction", producer="TestProducer")
    extracted = extract_pdf(pdf_bytes)
    assert extracted.page_count == 1
    assert extracted.text_extractable is True
    assert extracted.metadata.get("producer") == "TestProducer"
    assert extracted.md5 is not None
