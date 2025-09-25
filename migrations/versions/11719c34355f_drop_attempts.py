"""drop attempts

Revision ID: 11719c34355f
Revises: b3b6213d9236
Create Date: 2025-09-24 05:05:49.245939

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision: str = '11719c34355f'
down_revision: Union[str, Sequence[str], None] = 'b3b6213d9236'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.drop_column('scan_tasks', 'attempts')


def downgrade() -> None:
    """Downgrade schema."""
    pass
