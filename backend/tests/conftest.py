import pytest
import os
import sys
from fastapi.testclient import TestClient
from app.main import app
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker
from app.models import Base
from app.core.db import get_db


DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./test.db")
os.environ["DATABASE_URL"] = DATABASE_URL


@pytest.fixture(scope="session")
def db_engine():
    """Create test database engine using PostgreSQL or SQLite."""
    is_sqlite = DATABASE_URL.startswith("sqlite")
    connect_args = {"check_same_thread": False} if is_sqlite else {}
    engine = create_engine(DATABASE_URL, pool_pre_ping=not is_sqlite, connect_args=connect_args)
    
    if is_sqlite:
        Base.metadata.drop_all(bind=engine)
    else:
        # Drop all tables and indexes completely
        with engine.connect() as conn:
            conn.execute(text("""
                DROP TABLE IF EXISTS attack_path_steps CASCADE;
                DROP TABLE IF EXISTS attack_paths CASCADE;
                DROP TABLE IF EXISTS attack_graph_edges CASCADE;
                DROP TABLE IF EXISTS attack_graph_nodes CASCADE;
                DROP TABLE IF EXISTS attack_graphs CASCADE;
                DROP TABLE IF EXISTS finding_correlations CASCADE;
                DROP TABLE IF EXISTS workflow_attack_steps CASCADE;
                DROP TABLE IF EXISTS workflow_attack_scenarios CASCADE;
                DROP TABLE IF EXISTS workflow_step_executions CASCADE;
                DROP TABLE IF EXISTS workflow_executions CASCADE;
                DROP TABLE IF EXISTS workflow_transitions CASCADE;
                DROP TABLE IF EXISTS workflow_states CASCADE;
                DROP TABLE IF EXISTS workflow_steps CASCADE;
                DROP TABLE IF EXISTS workflows CASCADE;
                DROP TABLE IF EXISTS authentication_policies CASCADE;
                DROP TABLE IF EXISTS property_authorization_rules CASCADE;
                DROP TABLE IF EXISTS resource_properties CASCADE;
                DROP TABLE IF EXISTS endpoint_policy_allowed_roles CASCADE;
                DROP TABLE IF EXISTS endpoint_policy_denied_roles CASCADE;
                DROP TABLE IF EXISTS authorization_matrix_rules CASCADE;
                DROP TABLE IF EXISTS endpoint_authorization_policies CASCADE;
                DROP TABLE IF EXISTS evidence CASCADE;
                DROP TABLE IF EXISTS findings CASCADE;
                DROP TABLE IF EXISTS test_executions CASCADE;
                DROP TABLE IF EXISTS security_tests CASCADE;
                DROP TABLE IF EXISTS resource_ownerships CASCADE;
                DROP TABLE IF EXISTS identities CASCADE;
                DROP TABLE IF EXISTS roles CASCADE;
                DROP TABLE IF EXISTS endpoints CASCADE;
                DROP TABLE IF EXISTS resources CASCADE;
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
    is_sqlite = str(db_engine.url).startswith("sqlite")
    
    # Truncate all tables for clean state
    with db_engine.connect() as conn:
        for table in reversed(Base.metadata.sorted_tables):
            if is_sqlite:
                conn.execute(text(f'DELETE FROM "{table.name}"'))
            else:
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