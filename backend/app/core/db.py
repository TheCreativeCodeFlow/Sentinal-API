import os
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.ext.declarative import declarative_base

def get_database_url():
    return os.getenv(
        "DATABASE_URL",
        "postgresql://sentinel:sentinel@db:5432/sentinel",
    )


Base = declarative_base()


def get_engine():
    """Get the appropriate database engine."""
    db_url = get_database_url()
    connect_args = {"check_same_thread": False} if db_url.startswith("sqlite") else {}
    return create_engine(
        db_url,
        pool_pre_ping=not db_url.startswith("sqlite"),
        connect_args=connect_args,
        echo=False,
    )


def get_db():
    """Dependency to get DB session."""
    engine = get_engine()
    return sessionmaker(autocommit=False, autoflush=False, bind=engine)()


def create_tables(engine=None):
    """Create all tables."""
    if engine is None:
        engine = get_engine()
    Base.metadata.create_all(bind=engine)


def drop_tables(engine=None):
    """Drop all tables."""
    if engine is None:
        engine = get_engine()
    Base.metadata.drop_all(bind=engine)