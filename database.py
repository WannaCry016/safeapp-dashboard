from sqlalchemy import create_engine, text
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
import os
from dotenv import load_dotenv

load_dotenv()  # Load environment variables

DATABASE_URL = "postgresql://postgres:lastdance@localhost:5432/safeapp"

print(f"[DEBUG] Connecting to database: {DATABASE_URL}")  # Debugging statement

try:
    engine = create_engine(DATABASE_URL, echo=True)  # 'echo=True' enables SQL query logging
    connection = engine.connect()
    print("[DEBUG] Database connection established successfully.")

except Exception as e:
    print(f"[ERROR] Database connection failed: {e}")

SessionLocal = sessionmaker(bind=engine, autocommit=False, autoflush=False)
Base = declarative_base()

# Dependency to get DB session
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
