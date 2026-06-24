from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
REPORTS_DIR = BASE_DIR / "reports"
REFERENCE_DIR = BASE_DIR / "reference_receipts"
REFERENCE_PROFILES_FILE = REFERENCE_DIR / "profiles.json"

MAX_FILE_SIZE_BYTES = 10 * 1024 * 1024
ALLOWED_CONTENT_TYPE = "application/pdf"

FAKE_THRESHOLD = 0.7
SUSPICIOUS_THRESHOLD = 0.35

MAX_IMAGE_DPI = 300
MODDATE_LATER_THRESHOLD_SEC = 3600
