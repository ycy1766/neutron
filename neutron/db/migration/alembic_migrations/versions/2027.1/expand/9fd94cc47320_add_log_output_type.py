# Copyright 2026 KT Cloud
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.
#

import sqlalchemy as sa

from neutron.db import migration


# Add output_type to the logs table
#
# Revision ID: 9fd94cc47320
# Revises: d4b7e5f2a1c3
# Create Date: 2026-10-14 12:00:00.000000

# revision identifiers, used by Alembic.
revision = '9fd94cc47320'
down_revision = 'd4b7e5f2a1c3'


def upgrade():
    migration.add_column_if_not_exists(
        'logs',
        sa.Column('output_type', sa.String(length=16), nullable=False,
                  server_default='packet_log'))
