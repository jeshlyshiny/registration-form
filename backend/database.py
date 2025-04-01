# from sqlalchemy import create_engine
# from sqlalchemy.ext.declarative import declarative_base
# from sqlalchemy.orm import sessionmaker

# # PostgreSQL URL format
# DATABASE_URL = "postgresql://postgres:Shiny@localhost/expense_db"

# engine = create_engine(DATABASE_URL)
# SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
# Base = declarative_base()

# # Create tables
# Base.metadata.create_all(bind=engine)

# # ✅ Database Dependency
# def get_db():
#     db = SessionLocal() 
#     try:
#         yield db
#     finally:
#         db.close()

from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
import os
from dotenv import load_dotenv

# ✅ Load environment variables from .env
load_dotenv()

# ✅ PostgreSQL Connection URL (from environment variable for security)
DATABASE_URL = os.getenv("DATABASE_URL", "postgresql://postgres:Shiny@localhost/expense_db")

# ✅ Create the database engine
engine = create_engine(DATABASE_URL, echo=True)  # Set echo=True for debugging (remove in production)

# ✅ Session factory
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# ✅ Base class for models
Base = declarative_base()

# ✅ Database Dependency
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
