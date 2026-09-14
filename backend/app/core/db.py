import os
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.ext.declarative import declarative_base

DATABASE_URL = os.getenv(
    "DATABASE_URL",
    "postgresql://sentinel:sentinel@db:5432/sentinel",
)

Base = declarative_base()


def get_engine():
    """Get the appropriate database engine."""
    return create_engine(
        DATABASE_URL,
        pool_pre_ping=True,
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