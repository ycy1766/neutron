# Copyright (c) 2018 Fujitsu Limited
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
from neutron_lib import context as n_context
from neutron_lib.services.logapi import constants as log_const

from neutron.services.logapi.common import db_api
from neutron.services.logapi.common import validators
from neutron.services.logapi.drivers import manager


class SecurityGroupRuleCallBack(manager.ResourceCallBackBase):

    def handle_event(self, resource, event, trigger, payload):
        context = payload.context
        admin_context = n_context.get_admin_context()
        sg_rule = payload.latest_state
        if sg_rule:
            sg_id = sg_rule.get('security_group_id')
        else:
            sg_id = payload.resource_id

        # Log resources can only be fetched from admin context. The logs
        # of the project making the change are selected, and the
        # flow-sample logs of any project: they are administrative and must
        # follow every rule change of the security group they select.
        log_resources = [
            log_obj for log_obj in db_api.get_logs_bound_sg(
                admin_context, sg_id=sg_id)
            if (not context.project_id or
                log_obj.project_id == context.project_id or
                validators.get_log_output_type(log_obj) ==
                output_apidef.FLOW_SAMPLE)]
        if log_resources:
            self.resource_push_api(
                log_const.RESOURCE_UPDATE, context, log_resources)
