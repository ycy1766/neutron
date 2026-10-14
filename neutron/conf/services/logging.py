# Copyright 2017 Fujitsu Limited
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
#

from oslo_config import cfg

from neutron._i18n import _

log_driver_opts = [
    cfg.IntOpt(
        'rate_limit',
        default=100,
        min=100,
        help=_('Maximum packets logging per second.')),
    cfg.IntOpt(
        'burst_limit',
        default=25,
        min=25,
        help=_('Maximum number of packets per rate_limit.')),
    cfg.StrOpt(
        'local_output_log_base',
        help=_('Output logfile path on agent side, default syslog file.')),
]


# These options are only consumed by the ML2/OVN logging driver running in the
# Neutron server. They are registered separately from ``log_driver_opts``
# because the agents that register those options do not use them.
ovn_acl_sampling_opts = [
    cfg.BoolOpt(
        'ovn_acl_sampling',
        default=False,
        help=_('Allow network logs with the "flow_sample" output on the '
               'ML2/OVN logging driver. When enabled, Neutron manages the '
               'OVN Northbound Sampling_App rows of type "acl-new" and '
               '"acl-est" and one Sample_Collector, using the identifiers '
               'below, and attaches OVN Samples to the ACLs of the '
               'selected security groups. The identifiers and the '
               'probability have no defaults and must be set explicitly. '
               'The OVS Flow_Sample_Collector_Set and IPFIX exporter on '
               'each chassis are configured by the operator.')),
    cfg.IntOpt(
        'ovn_acl_sampling_app_new_id',
        min=1, max=255,
        help=_('ID of the OVN Sampling_App row of type "acl-new" that '
               'Neutron creates and owns. Required when '
               '"ovn_acl_sampling" is enabled.')),
    cfg.IntOpt(
        'ovn_acl_sampling_app_est_id',
        min=1, max=255,
        help=_('ID of the OVN Sampling_App row of type "acl-est" that '
               'Neutron creates and owns. It must differ from '
               '"ovn_acl_sampling_app_new_id". Required when '
               '"ovn_acl_sampling" is enabled.')),
    cfg.IntOpt(
        'ovn_acl_sampling_collector_id',
        min=1, max=255,
        help=_('ID of the OVN Sample_Collector row that Neutron creates and '
               'owns. Required when "ovn_acl_sampling" is enabled.')),
    cfg.IntOpt(
        'ovn_acl_sampling_collector_set_id',
        min=1, max=4294967295,
        help=_('OVS Flow_Sample_Collector_Set ID referenced by the Neutron '
               'Sample_Collector. Required when "ovn_acl_sampling" is '
               'enabled.')),
    cfg.IntOpt(
        'ovn_acl_sampling_probability',
        min=1, max=65535,
        help=_('Sampling probability of the Neutron Sample_Collector, '
               'expressed as N/65535. It applies to all sampled ACLs and '
               'connection stages. Required when "ovn_acl_sampling" is '
               'enabled.')),
]


def register_log_driver_opts(cfg=cfg.CONF):
    cfg.register_opts(log_driver_opts, 'network_log')


def register_ovn_acl_sampling_opts(cfg=cfg.CONF):
    cfg.register_opts(ovn_acl_sampling_opts, 'network_log')
