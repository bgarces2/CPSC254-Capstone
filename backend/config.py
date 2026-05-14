import os
from dotenv import load_dotenv

load_dotenv()

OPENAI_API_KEY: str = os.getenv("OPENAI_API_KEY", "")
OPENAI_MODEL: str = os.getenv("OPENAI_MODEL", "gpt-4o")

TARGET_BASE_URL: str = os.getenv("TARGET_BASE_URL", "http://localhost:3000")

MAX_FUZZ_ATTEMPTS: int = int(os.getenv("MAX_FUZZ_ATTEMPTS", "10"))

DATABASE_URL: str = os.getenv("DATABASE_URL", "slingshot.db")
