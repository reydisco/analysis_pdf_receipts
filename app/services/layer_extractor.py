import hashlib
import re
from datetime import datetime
from typing import Dict, List, Optional, Tuple

import fitz

MONTHS = {
    "январ": 1,
    "феврал": 2,
    "март": 3,
    "апрел": 4,
    "мая": 5,
    "ма": 5,
    "июн": 6,
    "июл": 7,
    "август": 8,
    "сентябр": 9,
    "октябр": 10,
    "ноябр": 11,
    "декабр": 12,
}


def compute_file_hashes(raw: bytes) -> Tuple[str, str]:
    return hashlib.md5(raw).hexdigest(), hashlib.sha256(raw).hexdigest()


def analyze_raw_structure(raw: bytes) -> Dict:
    return {
        "has_valid_header": raw.startswith(b"%PDF-"),
        "has_xref": b"xref" in raw,
        "has_trailer": b"trailer" in raw,
        "has_eof": b"%%EOF" in raw,
        "eof_count": raw.count(b"%%EOF"),
        "object_count": len(re.findall(rb"\d+ \d+ obj", raw)),
    }


def parse_pdf_meta_date(value: Optional[str]) -> Optional[datetime]:
    if not value:
        return None
    match = re.search(r"D:(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})", value)
    if not match:
        return None
    y, mo, d, h, mi, se = map(int, match.groups())
    return datetime(y, mo, d, h, mi, se)


def parse_text_operation_date(text: str) -> Optional[datetime]:
    match = re.search(
        r"(\d{1,2})\s+([а-яё]+)\s+(\d{4})\s+(\d{2}):(\d{2}):(\d{2})",
        text,
        re.IGNORECASE,
    )
    if match:
        day = int(match.group(1))
        month_word = match.group(2).lower()
        year = int(match.group(3))
        month = next(v for k, v in MONTHS.items() if month_word.startswith(k))
        return datetime(year, month, day, int(match.group(4)), int(match.group(5)), int(match.group(6)))

    match = re.search(r"(\d{2})[./](\d{2})[./](\d{4})\s+(\d{2}):(\d{2}):(\d{2})", text)
    if match:
        d, mo, y = int(match.group(1)), int(match.group(2)), int(match.group(3))
        return datetime(y, mo, d, int(match.group(4)), int(match.group(5)), int(match.group(6)))
    return None


def content_skeleton(content: str) -> str:
    skeleton = re.sub(r"-?\d+\.?\d*", "#", content)
    skeleton = re.sub(r"\([^)]*\)", "(STR)", skeleton)
    return skeleton


def tm_y_grid(content: str) -> List[float]:
    values = [round(float(y), 2) for _, y in re.findall(r"1 0 0 1 ([\d.-]+) ([\d.-]+) Tm", content)]
    return sorted(set(values))


def tm_positions(content: str) -> List[List[float]]:
    return [
        [round(float(x), 2), round(float(y), 2)]
        for x, y in re.findall(r"1 0 0 1 ([\d.-]+) ([\d.-]+) Tm", content)
    ]


def date_line_tm_at_y(
    positions: List[List[float]],
    expected_y: float,
    tolerance_y: float = 0.5,
) -> Optional[List[float]]:
    for x, y in positions:
        if abs(y - expected_y) <= tolerance_y:
            return [x, y]
    return None


def extract_layers(raw: bytes, text: str, creation_date_raw: Optional[str]) -> Dict:
    structure = analyze_raw_structure(raw)
    md5_hash, sha256_hash = compute_file_hashes(raw)

    doc = fitz.open(stream=raw, filetype="pdf")
    page = doc[0] if doc.page_count else None
    content = page.read_contents().decode("latin1", errors="replace") if page else ""
    skeleton = content_skeleton(content)
    y_grid = tm_y_grid(content)
    positions = tm_positions(content)

    base_fonts: List[str] = []
    font_details: List[Dict] = []
    font_types: List[str] = []
    if page:
        for font in page.get_fonts(full=True):
            basefont = font[3]
            font_type = font[2]
            base_fonts.append(basefont)
            font_details.append({"name": basefont, "type": font_type})
            font_types.append(font_type)

    images: List[Dict] = []
    image_hashes: List[str] = []
    if page:
        for img in page.get_images(full=True):
            xref = img[0]
            extracted = doc.extract_image(xref)
            pixel_md5 = hashlib.md5(extracted["image"]).hexdigest()
            images.append(
                {
                    "xref": xref,
                    "ext": extracted["ext"],
                    "width": extracted["width"],
                    "height": extracted["height"],
                    "xres": extracted.get("xres"),
                    "yres": extracted.get("yres"),
                    "pixel_md5": pixel_md5,
                }
            )
            image_hashes.append(pixel_md5)

    stream_hashes: Dict[str, str] = {}
    meta_dt = parse_pdf_meta_date(creation_date_raw)
    text_dt = parse_text_operation_date(text)
    delta_sec = (meta_dt - text_dt).total_seconds() if meta_dt and text_dt else None

    has_signature = b"/Type /Sig" in raw or b"/Type/Sig" in raw or (
        b"/SubFilter" in raw and b"/adbe.pkcs7" in raw
    )

    xref_length = doc.xref_length()
    is_repaired = doc.is_repaired
    doc.close()

    max_image_dpi = 0
    for img in images:
        for res in (img.get("xres"), img.get("yres")):
            if res and res > max_image_dpi:
                max_image_dpi = res

    return {
        **structure,
        "md5": md5_hash,
        "sha256": sha256_hash,
        "xref_length": xref_length,
        "is_repaired": is_repaired,
        "base_fonts": sorted(set(base_fonts)),
        "font_count": len(set(base_fonts)),
        "font_details": font_details,
        "font_types": sorted(set(font_types)),
        "max_image_dpi": max_image_dpi,
        "images": images,
        "image_count": len(images),
        "image_hashes": image_hashes,
        "content_skeleton_md5": hashlib.md5(skeleton.encode()).hexdigest()[:16],
        "tm_y_count": len(y_grid),
        "tm_y_grid": y_grid,
        "tm_positions": positions,
        "meta_text_delta_sec": delta_sec,
        "has_digital_signature": has_signature,
    }
