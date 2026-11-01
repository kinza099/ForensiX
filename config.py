import os

BASE_DIR = os.path.abspath(os.path.dirname(__file__))

SECRET_KEY = os.environ.get("SECRET_KEY", "forensix-ultra-secure-forensics-key-2026")
DATABASE_PATH = os.path.join(BASE_DIR, "forensix.db")

RAW_VAULT_DIR = os.path.join(BASE_DIR, "evidence_vault", "raw")
EXTRACTED_VAULT_DIR = os.path.join(BASE_DIR, "evidence_vault", "extracted")
REPORTS_DIR = os.path.join(BASE_DIR, "evidence_vault", "reports")

os.makedirs(RAW_VAULT_DIR, exist_ok=True)
os.makedirs(EXTRACTED_VAULT_DIR, exist_ok=True)
os.makedirs(REPORTS_DIR, exist_ok=True)

MAX_CONTENT_LENGTH = 100 * 1024 * 1024  # 100 MB max upload limit

DEFAULT_INVESTIGATOR = {
    "username": "investigator",
    "password": "forensix2026",
    "full_name": "Senior Investigator Alex Vance",
    "role": "Lead Digital Forensic Analyst"
}
