"""Add connector_name to event_sources and incident_management_asset

Revision ID: 6fcb41ff090b
Revises: 76f5e57eb47a
Create Date: 2026-09-10 00:00:00.000000

"""
from typing import Sequence
from typing import Union

import sqlalchemy as sa
import sqlmodel.sql.sqltypes

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "6fcb41ff090b"
down_revision: Union[str, None] = "76f5e57eb47a"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # server_default on both columns is scaffolding for adding them to populated
    # tables; it comes off at the end so the columns match the model, which
    # declares Python-side defaults only. Every existing row resolves to the
    # Wazuh indexer, which is the cluster they've always been queried against.
    op.add_column(
        "event_sources",
        sa.Column(
            "connector_name",
            sqlmodel.sql.sqltypes.AutoString(length=255),
            nullable=False,
            server_default="Wazuh-Indexer",
        ),
    )
    op.add_column(
        "incident_management_asset",
        sa.Column(
            "connector_name",
            sqlmodel.sql.sqltypes.AutoString(length=255),
            nullable=False,
            server_default="Wazuh-Indexer",
        ),
    )

    op.alter_column("event_sources", "connector_name", existing_type=sa.String(255), server_default=None)
    op.alter_column("incident_management_asset", "connector_name", existing_type=sa.String(255), server_default=None)


def downgrade() -> None:
    op.drop_column("incident_management_asset", "connector_name")
    op.drop_column("event_sources", "connector_name")
