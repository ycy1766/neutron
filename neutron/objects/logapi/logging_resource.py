# Copyright (c) 2017 Fujitsu Limited
# All Rights Reserved.
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

from neutron_lib.api.definitions import logging_output_type as output_apidef
from neutron_lib.objects import common_types
from neutron_lib.objects.logapi import event_types
from neutron_lib.services.logapi import constants as log_const
from oslo_utils import versionutils
from oslo_versionedobjects import exception as obj_exception
from oslo_versionedobjects import fields as obj_fields

from neutron.db.models import loggingapi as log_db
from neutron.objects import base


@base.NeutronObjectRegistry.register
class Log(base.NeutronDbObject):
    # Version 1.0: Initial version
    # Version 1.1: Add output_type
    VERSION = '1.1'

    db_model = log_db.Log

    fields = {
        'id': common_types.UUIDField(),
        'project_id': obj_fields.StringField(nullable=True),
        'name': obj_fields.StringField(nullable=True),
        'resource_type': obj_fields.StringField(),
        'resource_id': common_types.UUIDField(nullable=True, default=None),
        'target_id': common_types.UUIDField(nullable=True, default=None),
        'event': event_types.SecurityEventField(default=log_const.ALL_EVENT),
        'enabled': obj_fields.BooleanField(default=True),
        'output_type': obj_fields.StringField(
            default=output_apidef.PACKET_LOG),
    }

    fields_no_update = ['project_id', 'resource_type', 'resource_id',
                        'target_id', 'event', 'output_type']

    def obj_make_compatible(self, primitive, target_version):
        _target_version = versionutils.convert_version_to_tuple(target_version)
        if _target_version < (1, 1):
            # A consumer of the older version would treat any log as a
            # request for packet logging, so a log with another output
            # cannot be represented.
            output_type = primitive.pop('output_type',
                                        output_apidef.PACKET_LOG)
            if output_type != output_apidef.PACKET_LOG:
                raise obj_exception.IncompatibleObjectVersion(
                    objname=self.__class__.__name__,
                    objver=target_version, supported='1.1')
