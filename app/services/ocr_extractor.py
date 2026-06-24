from typing import Tuple

import fitz


def ocr_pdf_text(pdf_bytes: bytes) -> Tuple[str, bool]:
    try:
        import pytesseract
        from PIL import Image
    except ImportError:
        return "", False

    try:
        doc = fitz.open(stream=pdf_bytes, filetype="pdf")
        if doc.page_count == 0:
            doc.close()
            return "", False
        page = doc[0]
        pix = page.get_pixmap(dpi=200)
        image = Image.frombytes("RGB", (pix.width, pix.height), pix.samples)
        text = pytesseract.image_to_string(image, lang="rus+eng")
        doc.close()
        cleaned = text.strip()
        return cleaned, len(cleaned) > 20
    except Exception:
        return "", False
