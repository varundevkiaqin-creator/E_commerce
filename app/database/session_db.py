import os
import pymysql
from dotenv import load_dotenv
from pathlib import Path

# Load the project's exact .env file
BASE_DIR = Path(__file__).resolve().parents[2]
ENV_FILE = BASE_DIR / ".env"

load_dotenv(ENV_FILE, override=True)


def get_db():
    return pymysql.connect(
        host=os.getenv("DB_HOST", "127.0.0.1"),
        port=int(os.getenv("DB_PORT", "3306")),
        user=os.getenv("DB_USER", "root"),
        password=os.getenv("DB_PASSWORD"),
        database=os.getenv("DB_NAME", "ecommerce_db"),
        cursorclass=pymysql.cursors.DictCursor,
        autocommit=False,
    )
