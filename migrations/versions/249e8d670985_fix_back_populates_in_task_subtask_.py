"""Fix back_populates in Task, Subtask, Comment

Revision ID: 249e8d670985
Revises: 3f1a309a6a82
Create Date: 2025-01-08 14:14:57.160743

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '249e8d670985'
down_revision: Union[str, None] = '3f1a309a6a82'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # ### commands auto generated by Alembic - please adjust! ###
    pass
    # ### end Alembic commands ###


def downgrade() -> None:
    # ### commands auto generated by Alembic - please adjust! ###
    pass
    # ### end Alembic commands ###
