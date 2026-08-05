"""Alembic environment for the independent publisher database."""

from logging.config import fileConfig

from alembic import context
from sqlalchemy import engine_from_config, pool, text

from traceless_api.publisher import db_v2  # noqa: F401
from traceless_api.publisher.config import PublisherSettings
from traceless_api.publisher.db import PublisherBase

config = context.config
if config.config_file_name is not None:
    fileConfig(config.config_file_name)

settings = PublisherSettings()
config.set_main_option("sqlalchemy.url", settings.database_url.replace("%", "%%"))
target_metadata = PublisherBase.metadata


def run_migrations_offline() -> None:
    context.configure(
        url=config.get_main_option("sqlalchemy.url"),
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
        compare_type=True,
    )
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    connectable = engine_from_config(
        config.get_section(config.config_ini_section, {}),
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )
    with connectable.connect() as connection:
        if settings.migration_role is not None:
            # SET ROLE starts SQLAlchemy's implicit transaction. Commit that
            # transaction first so Alembic owns and commits the migration
            # transaction instead of having all DDL rolled back on disconnect.
            connection.execute(text(f'SET ROLE "{settings.migration_role}"'))
            connection.commit()
        context.configure(
            connection=connection,
            target_metadata=target_metadata,
            compare_type=True,
        )
        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
