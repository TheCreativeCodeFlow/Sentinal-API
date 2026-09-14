import pytest
import os
import sys
from fastapi.testclient import TestClient
from app.main import app
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker
from app.models import Base
from app.core.db import get_db


DATABASE_URL = os.getenv("DATABASE_URL", "postgresql://sentinel:sentinel@localhost:5432/sentinel")


@pytest.fixture(scope="session")
def db_engine():
    """Create test database engine using PostgreSQL."""
    engine = create_engine(DATABASE_URL, pool_pre_ping=True)
    
    # Drop all tables and indexes completely
    with engine.connect() as conn:
        conn.execute(text("""
            DROP TABLE IF EXISTS endpoints CASCADE;
            DROP TABLE IF EXISTS schemas CASCADE;
            DROP TABLE IF EXISTS auth_schemes CASCADE;
            DROP TABLE IF EXISTS apis CASCADE;
            DROP TABLE IF EXISTS projects CASCADE;
        """))
        conn.commit()
    
    Base.metadata.create_all(bind=engine)
    yield engine
    engine.dispose()


@pytest.fixture(scope="function")
def db_session(db_engine):
    """Create a new session for each test, truncating tables for clean state."""
    from app.models import Base
    
    # Truncate all tables for clean state
    with db_engine.connect() as conn:
        for table in reversed(Base.metadata.sorted_tables):
            conn.execute(text(f'TRUNCATE TABLE "{table.name}" RESTART IDENTITY CASCADE'))
        conn.commit()
    
    SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=db_engine)
    session = SessionLocal()
    
    # Override the database dependency
    def override_get_db():
        try:
            yield session
        finally:
            pass
    
    app.dependency_overrides[get_db] = override_get_db
    
    yield session
    
    session.close()
    app.dependency_overrides.clear()


@pytest.fixture(scope="function")
def client(db_session):
    """Test client fixture that depends on db_session to ensure override is applied."""
    return TestClient(app)