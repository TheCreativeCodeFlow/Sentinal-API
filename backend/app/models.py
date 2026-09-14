from sqlalchemy import (
    Column,
    Integer,
    String,
    Text,
    DateTime,
    Boolean,
    ForeignKey,
    Index,
)
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func
from app.core.db import Base


class Project(Base):
    __tablename__ = "projects"

    id = Column(Integer, primary_key=True)
    name = Column(String(200), nullable=False, index=True)
    description = Column(Text, nullable=True)
    environment = Column(String(100), nullable=False, default="production", index=True)
    base_url = Column(Text, nullable=True)
    authorization_status = Column(
        String(50), nullable=False, default="pending", index=True
    )
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    updated_at = Column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False
    )

    apis = relationship("API", back_populates="project", cascade="all, delete-orphan")


class API(Base):
    __tablename__ = "apis"

    id = Column(Integer, primary_key=True)
    project_id = Column(Integer, ForeignKey("projects.id", ondelete="CASCADE"), nullable=False, index=True)
    name = Column(String(200), nullable=False, index=True)
    version = Column(String(50), nullable=True)
    title = Column(String(200), nullable=True)
    url = Column(Text, nullable=True)
    format = Column(String(20), nullable=False, default="openapi3")
    status = Column(String(50), nullable=False, default="pending", index=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    updated_at = Column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False
    )

    project = relationship("Project", back_populates="apis")
    endpoints = relationship("Endpoint", back_populates="api", cascade="all, delete-orphan")


class Endpoint(Base):
    __tablename__ = "endpoints"

    id = Column(Integer, primary_key=True)
    api_id = Column(Integer, ForeignKey("apis.id", ondelete="CASCADE"), nullable=False)
    method = Column(String(10), nullable=False)
    path = Column(String(500), nullable=False)
    summary = Column(Text, nullable=True)
    description = Column(Text, nullable=True)
    tags = Column(Text, nullable=True)
    description_raw = Column(Text, nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)

    api = relationship("API", back_populates="endpoints")

    __table_args__ = (
        Index("ix_endpoints_api_id", "api_id"),
        Index("ix_endpoints_method_path", "method", "path", unique=True),
    )


class Schema(Base):
    __tablename__ = "schemas"

    id = Column(Integer, primary_key=True)
    name = Column(String(200), nullable=False)
    content = Column(Text, nullable=False)
    format = Column(String(20), nullable=False, default="openapi3")
    source = Column(String(100), nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    updated_at = Column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False
    )

    __table_args__ = (
        Index("ix_schemas_name", "name"),
    )


class AuthScheme(Base):
    __tablename__ = "auth_schemes"

    id = Column(Integer, primary_key=True)
    name = Column(String(200), nullable=False)
    type = Column(String(50), nullable=False, index=True)
    description = Column(Text, nullable=True)
    auth_in = Column(String(50), nullable=True)  # query, header, body
    scheme = Column(String(100), nullable=True)  # bearer, basic
    bearer_format = Column(String(100), nullable=True)
    description_raw = Column(Text, nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)

    __table_args__ = (
        Index("ix_auth_schemes_name", "name"),
    )