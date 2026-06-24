import hashlib
import re
from typing import Dict, List, Optional, Tuple

import fitz


def _stream_kind(obj: str, raw: bytes) -> str:
    if "/Subtype/Image" in obj or "/Subtype /Image" in obj:
        return "image"
    if raw[:4] == b"\x00\x01\x00\x00" or b"fpgm" in raw[:2048]:
        return "font"
    if b"/CIDInit" in raw or b"CIDSystemInfo" in raw:
        return "cid_init"
    if b" Tm" in raw or b" BT" in raw:
        return "content"
    return "other"


def analyze_pdf_streams(raw: bytes) -> Tuple[Dict[str, str], List[Dict], Dict[str, List[str]]]:
    doc = fitz.open(stream=raw, filetype="pdf")
    stream_hashes: Dict[str, str] = {}
    stream_details: List[Dict] = []
    by_kind: Dict[str, List[str]] = {
        "image": [],
        "font": [],
        "content": [],
        "cid_init": [],
        "other": [],
    }

    for xref in range(1, doc.xref_length()):
        if not doc.xref_is_stream(xref):
            continue
        obj = doc.xref_object(xref, compressed=False) or ""
        data = doc.xref_stream(xref) or b""
        kind = _stream_kind(obj, data)
        digest = hashlib.md5(data).hexdigest()[:16]
        key = str(xref)
        stream_hashes[key] = digest
        stream_details.append(
            {
                "xref": xref,
                "kind": kind,
                "md5": digest,
                "size": len(data),
            }
        )
        by_kind[kind].append(digest)

    doc.close()
    return stream_hashes, stream_details, by_kind


def generator_fingerprint(by_kind: Dict[str, List[str]]) -> str:
    parts = []
    for kind in ("content", "font", "cid_init"):
        for digest in sorted(by_kind.get(kind, [])):
            parts.append(f"{kind}:{digest}")
    return "|".join(parts) if parts else "empty"
