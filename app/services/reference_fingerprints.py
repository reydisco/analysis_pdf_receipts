from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

from app.config import REFERENCE_DIR
from app.services.pdf_extractor import extract_pdf


def stream_hash_values(stream_hashes: Dict[str, str]) -> Set[str]:
    return set(stream_hashes.values())


def load_pdf_fingerprint(pdf_path: Path) -> Dict:
    extracted = extract_pdf(pdf_path.read_bytes())
    return {
        "filename": pdf_path.name,
        "md5": extracted.md5,
        "sha256": extracted.sha256,
        "stream_hashes": extracted.stream_hashes,
        "stream_values": sorted(stream_hash_values(extracted.stream_hashes)),
        "content_skeleton_md5": extracted.content_skeleton_md5,
        "image_hashes": extracted.image_hashes,
    }


def load_reference_pdf_fingerprints() -> List[Dict]:
    fingerprints: List[Dict] = []
    if not REFERENCE_DIR.exists():
        return fingerprints
    for pdf_path in sorted(REFERENCE_DIR.glob("*.pdf")):
        try:
            fingerprints.append(load_pdf_fingerprint(pdf_path))
        except Exception:
            continue
    return fingerprints


def merge_profile_fingerprints(bank_profile: Optional[Dict]) -> Dict:
    fake_streams = list(
        (bank_profile or {}).get("fake_generator_stream_hashes")
        or (bank_profile or {}).get("forbidden_stream_hashes")
        or []
    )
    return {
        "forbidden_file_md5": list((bank_profile or {}).get("forbidden_file_md5") or []),
        "forbidden_file_sha256": list((bank_profile or {}).get("forbidden_file_sha256") or []),
        "required_image_stream_hashes": list((bank_profile or {}).get("required_image_stream_hashes") or []),
        "fake_generator_stream_hashes": fake_streams,
        "skeleton_image_stream_hashes": dict(
            (bank_profile or {}).get("skeleton_image_stream_hashes") or {}
        ),
    }


def compare_generator_streams(
    file_streams: Dict[str, str],
    stream_details: List[Dict],
    required_images: List[str],
    fake_generator_hashes: List[str],
) -> Tuple[List[str], List[str], List[str]]:
    values = stream_hash_values(file_streams)
    image_hashes = [item["md5"] for item in stream_details if item.get("kind") == "image"]
    generator_hashes = [
        item["md5"]
        for item in stream_details
        if item.get("kind") in {"content", "font", "cid_init"}
    ]

    missing_images = sorted(set(required_images) - set(image_hashes))
    found_fake = sorted(set(fake_generator_hashes) & values)

    return missing_images, found_fake, generator_hashes
