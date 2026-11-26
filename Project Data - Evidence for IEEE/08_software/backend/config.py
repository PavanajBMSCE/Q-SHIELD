
import os

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

class Config:
    SECRET_KEY = os.environ.get(
        "SECRET_KEY",
        "qshield-local-development-key"
    )

    DATABASE_PATH = os.path.join(
        BASE_DIR, "database", "qshield.db"
    )

    UPLOAD_FOLDER = os.path.join(BASE_DIR, "uploads")

    MAX_CONTENT_LENGTH = 45 * 1024 * 1024  # 45 MB total for two comparison ZIP uploads

    ALLOWED_EXTENSIONS = {"zip"}
