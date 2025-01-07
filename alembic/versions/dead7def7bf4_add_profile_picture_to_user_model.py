"""Add profile_picture to User model

Revision ID: dead7def7bf4
Revises: 
Create Date: 2025-01-07 09:18:07.640457

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision: str = 'dead7def7bf4'
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # ### commands auto generated by Alembic - please adjust! ###
    op.add_column('users', sa.Column('profile_picture', sa.String(length=120), nullable=True))
    op.alter_column('users', 'username',
               existing_type=sa.VARCHAR(length=50),
               type_=sa.String(length=80),
               existing_nullable=False)
    op.alter_column('users', 'full_name',
               existing_type=sa.VARCHAR(length=100),
               nullable=False)
    op.alter_column('users', 'email',
               existing_type=sa.VARCHAR(length=100),
               type_=sa.String(length=120),
               existing_nullable=False)
    op.alter_column('users', 'password_hash',
               existing_type=sa.VARCHAR(length=255),
               type_=sa.String(length=128),
               existing_nullable=False)
    op.drop_column('users', 'created_at')
    # ### end Alembic commands ###


def downgrade() -> None:
    # ### commands auto generated by Alembic - please adjust! ###
    op.add_column('users', sa.Column('created_at', postgresql.TIMESTAMP(), autoincrement=False, nullable=True))
    op.alter_column('users', 'password_hash',
               existing_type=sa.String(length=128),
               type_=sa.VARCHAR(length=255),
               existing_nullable=False)
    op.alter_column('users', 'email',
               existing_type=sa.String(length=120),
               type_=sa.VARCHAR(length=100),
               existing_nullable=False)
    op.alter_column('users', 'full_name',
               existing_type=sa.VARCHAR(length=100),
               nullable=True)
    op.alter_column('users', 'username',
               existing_type=sa.String(length=80),
               type_=sa.VARCHAR(length=50),
               existing_nullable=False)
    op.drop_column('users', 'profile_picture')
    # ### end Alembic commands ###
