"""Engine and request-scoped session helpers."""

from collections.abc import Iterator
from uuid import UUID

from fastapi import Request
from sqlalchemy import Connection, Engine, create_engine, event, text
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from traceless_api.db.base import Base

_TENANT_RLS_SCOPE_KEY = "traceless.organization_id"


@event.listens_for(Session, "after_begin")
def _restore_tenant_rls_scope(
    session: Session,
    transaction: object,
    connection: Connection,
) -> None:
    """Re-apply the transaction-local tenant GUC after every commit boundary."""

    if getattr(transaction, "nested", False) or connection.dialect.name != "postgresql":
        return
    organization_id = session.info.get(_TENANT_RLS_SCOPE_KEY)
    if organization_id is None:
        return
    connection.execute(
        text("SELECT set_config('traceless.organization_id', :organization_id, true)"),
        {"organization_id": organization_id},
    )


def create_database_engine(database_url: str) -> Engine:
    """Create an engine with safe SQLite behavior for local tests."""

    kwargs: dict[str, object] = {"pool_pre_ping": True}
    if database_url.startswith("sqlite"):
        kwargs["connect_args"] = {"check_same_thread": False}
        if ":memory:" in database_url:
            kwargs["poolclass"] = StaticPool
    engine = create_engine(database_url, **kwargs)
    if database_url.startswith("sqlite"):

        @event.listens_for(engine, "connect")
        def enable_sqlite_foreign_keys(dbapi_connection: object, _: object) -> None:
            cursor = dbapi_connection.cursor()  # type: ignore[attr-defined]
            try:
                cursor.execute("PRAGMA foreign_keys=ON")
            finally:
                cursor.close()

    return engine


def create_session_factory(engine: Engine) -> sessionmaker[Session]:
    return sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)


def create_schema(engine: Engine) -> None:
    """Create local/test tables; production uses Alembic instead."""

    # Import registers every table on Base.metadata.
    from traceless_api.db import models  # noqa: F401

    Base.metadata.create_all(engine)


def apply_tenant_rls_scope(session: Session, organization_id: UUID) -> None:
    """Bind every transaction created by this session to one immutable tenant."""

    normalized = str(organization_id)
    existing = session.info.get(_TENANT_RLS_SCOPE_KEY)
    if existing is not None and existing != normalized:
        raise RuntimeError("A database session cannot be rebound to another organization")
    session.info[_TENANT_RLS_SCOPE_KEY] = normalized
    if session.get_bind().dialect.name != "postgresql" or not session.in_transaction():
        return
    # A transaction may have started before authentication bound the session.
    # Future transactions are handled by the after_begin listener above.
    session.connection().execute(
        text("SELECT set_config('traceless.organization_id', :organization_id, true)"),
        {"organization_id": normalized},
    )


def get_session(request: Request) -> Iterator[Session]:
    """Yield one transaction boundary for an HTTP request."""

    factory: sessionmaker[Session] = request.app.state.session_factory
    with factory() as session:
        try:
            yield session
            session.commit()
        except Exception:
            session.rollback()
            raise
