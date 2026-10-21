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

import collections
from collections import namedtuple
import secrets

from neutron_lib.api.definitions import logging_output_type as output_apidef
from neutron_lib.api.definitions import portbindings
from neutron_lib.callbacks import resources
from neutron_lib import exceptions as n_exceptions
from neutron_lib.plugins import constants as plugin_constants
from neutron_lib.plugins import directory
from neutron_lib.services.logapi import constants as log_const
from oslo_config import cfg
from oslo_log import log as logging
from oslo_utils import importutils
from ovsdbapp.backend.ovs_idl import idlutils

from neutron._i18n import _
from neutron.common.ovn import acl as acl_utils
from neutron.common.ovn import constants as ovn_const
from neutron.common.ovn import sampling as ovn_sampling
from neutron.common.ovn import utils
from neutron.conf.services import logging as log_cfg
from neutron.objects import securitygroup as sg_obj
from neutron.services.logapi.common import db_api
from neutron.services.logapi.common import exceptions as log_exc
from neutron.services.logapi.common import sg_callback
from neutron.services.logapi.common import validators
from neutron.services.logapi.drivers import base
from neutron.services.logapi.drivers import manager

LOG = logging.getLogger(__name__)

DRIVER = None

log_cfg.register_log_driver_opts()
log_cfg.register_ovn_acl_sampling_opts()

MAX_INT_LABEL = 2**32
SUPPORTED_LOGGING_TYPES = (log_const.SECURITY_GROUP,)
# Attempts of a sampling transaction when two servers allocate the same
# Sample metadata at the same time.
SAMPLING_TXN_ATTEMPTS = 3
# Extra sampling transactions when the stored logs changed while one was
# committed.
SAMPLING_RECHECKS = 2

OUTPUT_PACKET_LOG = output_apidef.PACKET_LOG
OUTPUT_FLOW_SAMPLE = output_apidef.FLOW_SAMPLE
DROP_LOG_EVENTS = (log_const.DROP_EVENT, log_const.ALL_EVENT)

log_output_type = validators.get_log_output_type


def is_flow_sample_log(log_obj):
    return log_output_type(log_obj) == OUTPUT_FLOW_SAMPLE


class LoggingNotSupported(n_exceptions.NeutronException):
    message = _("The current OVN version does not offer support "
                "for neutron network log functionality.")


class FlowSamplingNotAvailable(n_exceptions.InvalidInput):
    message = _("OVN ACL sampling is not enabled in the Neutron "
                "configuration or not supported by the OVN Northbound "
                "database.")


class OVNDriver(base.DriverBase):

    def __init__(self):
        super().__init__(
            name="ovn",
            vif_types=[portbindings.VIF_TYPE_OVS,
                       portbindings.VIF_TYPE_VHOST_USER],
            vnic_types=[portbindings.VNIC_NORMAL],
            supported_logging_types=SUPPORTED_LOGGING_TYPES,
            requires_rpc=False,
            supported_output_types=(OUTPUT_PACKET_LOG, OUTPUT_FLOW_SAMPLE))
        self._log_plugin_property = None
        self.meter_name = (
            cfg.CONF.network_log.local_output_log_base or "acl_log_meter")
        # An inconsistent sampling configuration stops the server at
        # startup instead of being reported on every request.
        ovn_sampling.SamplingConfig.from_conf(cfg.CONF.network_log)

    @classmethod
    def create(cls, plugin_driver):
        cls.plugin_driver = plugin_driver
        return OVNDriver()

    @property
    def available_output_types(self):
        """Advertise flow sampling only when it can be applied.

        Flow-sample logs are still dispatched to this driver while sampling
        is turned off, so that they can be disabled and deleted.
        """
        output_types = [OUTPUT_PACKET_LOG]
        if self._flow_sampling_available():
            output_types.append(OUTPUT_FLOW_SAMPLE)
        return tuple(output_types)

    @property
    def _log_plugin(self):
        if self._log_plugin_property is None:
            self._log_plugin_property = directory.get_plugin(
                plugin_constants.LOG_API)
        return self._log_plugin_property

    @staticmethod
    def _log_dict_to_obj(log_dict):
        cls = namedtuple('Log_obj', log_dict)
        cls.__new__.__defaults__ = tuple(log_dict.values())
        return cls()

    def _get_logs(self, context, **filters):
        log_objs = self._log_plugin.get_logs(
            context, filters=filters or None)
        return [self._log_dict_to_obj(lo) for lo in log_objs]

    def _get_packet_logs(self, context, **filters):
        """Return the log objects using the packet logging output."""
        return self._get_logs(context, output_type=OUTPUT_PACKET_LOG,
                              **filters)

    def _get_flow_sample_logs(self, context, **filters):
        """Return the log objects using the flow sampling output."""
        return self._get_logs(context, output_type=OUTPUT_FLOW_SAMPLE,
                              **filters)

    @property
    def _ovn_client(self):
        return self.plugin_driver._ovn_client

    @property
    def ovn_nb(self):
        return self.plugin_driver.nb_ovn

    @staticmethod
    def _acl_actions_enabled(log_obj):
        if not log_obj.enabled:
            return set()
        if log_obj.event == log_const.ACCEPT_EVENT:
            return {ovn_const.ACL_ACTION_ALLOW_RELATED,
                    ovn_const.ACL_ACTION_ALLOW_STATELESS,
                    ovn_const.ACL_ACTION_ALLOW}
        if log_obj.event == log_const.DROP_EVENT:
            return {ovn_const.ACL_ACTION_DROP,
                    ovn_const.ACL_ACTION_REJECT}
        # Fall through case: log_const.ALL_EVENT
        return {ovn_const.ACL_ACTION_DROP,
                ovn_const.ACL_ACTION_REJECT,
                ovn_const.ACL_ACTION_ALLOW_RELATED,
                ovn_const.ACL_ACTION_ALLOW_STATELESS,
                ovn_const.ACL_ACTION_ALLOW}

    @staticmethod
    def _acl_log_needs_update(acl, expected_log, log_name, meter_name):
        """Return True if the ACL logging attributes need to be updated."""
        return (acl.log != expected_log or
                acl.name != [log_name] or
                acl.meter != [meter_name] or
                acl.severity != ['info'] or
                acl.label == 0)

    def _remove_acls_log(self, pgs, ovn_txn, log_name=None):
        acl_absents, acl_changes, acl_visits = 0, 0, 0
        for pg in pgs:
            for acl_uuid in pg["acls"]:
                acl_visits += 1
                acl = self.ovn_nb.lookup("ACL", acl_uuid, default=None)
                # Log message if ACL is not found, as deleted concurrently
                if acl is None:
                    LOG.debug("ACL %s not found, deleted concurrently",
                              acl_uuid)
                    acl_absents += 1
                    continue
                # skip acls used by a different network log
                if log_name:
                    if acl.name and acl.name[0] != log_name:
                        continue
                columns = {
                    'log': False,
                    'meter': [],
                    'name': [],
                    'severity': [],
                    'label': 0,
                }
                ovn_txn.add(self.ovn_nb.db_remove(
                    "ACL", acl_uuid, 'options', 'log-related',
                    if_exists=True))
                ovn_txn.add(self.ovn_nb.db_set(
                    "ACL", acl_uuid, *columns.items()))
                acl_changes += 1
        msg = "Cleared %d, Not found %d (out of %d visited) ACLs"
        if log_name:
            msg += f" for network log {log_name}"
        LOG.info(msg, acl_changes, acl_absents, acl_visits)

    def _set_acls_log(self, pgs, context, ovn_txn, actions_enabled, log_name):
        acl_changes, acl_visits = 0, 0
        for pg in pgs:
            meter_name = self.meter_name
            if pg["name"] != ovn_const.OVN_DROP_PORT_GROUP_NAME:
                if ovn_const.OVN_SG_EXT_ID_KEY not in pg["external_ids"]:
                    LOG.info("Port Group %s is not part of any security "
                             "group, skipping its network log "
                             "setting...", pg["name"])
                    continue
                sg_id = pg["external_ids"][ovn_const.OVN_SG_EXT_ID_KEY]
                sg_stateful = sg_obj.SecurityGroup.get_sgs_stateful_flag(
                    context, [sg_id])
                if sg_id not in sg_stateful:
                    LOG.warning("Port Group %s is missing a corresponding "
                                "security group, skipping its network log "
                                "setting...", pg["name"])
                    continue
                if not sg_stateful[sg_id]:
                    meter_name = meter_name + ("_stateless")
            for acl_uuid in pg["acls"]:
                acl_visits += 1
                acl = self.ovn_nb.lookup("ACL", acl_uuid)
                # skip acls used by a different network log
                if acl.name and acl.name[0] != log_name:
                    continue

                expected_log = acl.action in actions_enabled
                if not self._acl_log_needs_update(
                        acl, expected_log, log_name, meter_name):
                    continue

                # Don't claim ACLs whose action is not relevant to this
                # log object; otherwise a DROP log would claim the allow
                # ACLs and block a later ALL/ACCEPT log from updating them.
                if not acl.name and acl.action not in actions_enabled:
                    continue

                columns = {
                    'log': expected_log,
                    'meter': meter_name,
                    'name': log_name,
                    'severity': "info",
                    'label': self._acl_log_label(acl),
                    'options': {'log-related': "true"},
                }
                ovn_txn.add(self.ovn_nb.db_set(
                    "ACL", acl_uuid, *columns.items()))
                acl_changes += 1
        LOG.info("Set %d (out of %d visited) ACLs for network log %s",
                 acl_changes, acl_visits, log_name)

    @staticmethod
    def _acl_log_label(acl):
        """Return the label to use for a logged ACL.

        A nonzero label takes precedence over the Sample metadata as the
        observation point emitted by OVN sampling. If Neutron samples the
        ACL, reuse the new-stage Sample metadata so that adding packet
        logging does not change the emitted value.
        """
        if ovn_sampling.referenced_sample(acl, ovn_sampling.STAGE_NEW):
            metadata = ovn_sampling.recorded_metadata(
                acl, ovn_sampling.STAGE_NEW)
            if metadata:
                return metadata
        return secrets.SystemRandom().randrange(1, MAX_INT_LABEL)

    def _update_log_objs(self, context, ovn_txn, log_objs):
        for log_obj in log_objs:
            pgs = self._pgs_from_log_obj(context, log_obj)
            actions_enabled = self._acl_actions_enabled(log_obj)
            log_name = utils.ovn_name(log_obj.id)
            self._set_acls_log(pgs, context, ovn_txn, actions_enabled,
                               log_name)
            if log_obj.enabled:
                self._create_sg_drop_acls(context, log_obj, ovn_txn,
                                          log_name)

    def _pgs_all(self):
        return self.ovn_nb.db_list(
            "Port_Group",
            columns=["name", "external_ids", "acls"]).execute(check_error=True)

    def _pgs_from_log_obj(self, context, log_obj):
        """Map Neutron log_obj into affected port groups in OVN.

        :param context: current running context information
        :param log_obj: a log_object to be analyzed.

        """
        if not log_obj.resource_id and not log_obj.target_id:
            # No sg, no port, ALL: return all pgs
            if log_obj.event == log_const.ALL_EVENT:
                return self._pgs_all()
            try:
                pg_drop = self.ovn_nb.lookup(
                    "Port_Group", ovn_const.OVN_DROP_PORT_GROUP_NAME)
                # No sg, no port, DROP: return DROP pg
                if log_obj.event == log_const.DROP_EVENT:
                    return [{"name": pg_drop.name,
                             "external_ids": pg_drop.external_ids,
                             "acls": [r.uuid for r in pg_drop.acls]}]
                # No sg, no port, ACCEPT: return all except DROP pg
                pgs = self._pgs_all()
                pgs.remove({"name": pg_drop.name,
                            "external_ids": pg_drop.external_ids,
                            "acls": [r.uuid for r in pg_drop.acls]})
                return pgs
            except idlutils.RowNotFound:
                pass
        return self._get_sg_port_groups(context, log_obj)

    def _get_sg_port_groups(self, context, log_obj):
        """Get port groups for the security groups targeted by a log object."""
        pgs = []
        if log_obj.resource_id:
            try:
                pg = self.ovn_nb.lookup("Port_Group",
                                        utils.ovn_port_group_name(
                                            log_obj.resource_id))
                pgs.append({"name": pg.name,
                            "external_ids": pg.external_ids,
                            "acls": [r.uuid for r in pg.acls]})
            except idlutils.RowNotFound:
                pass
        elif log_obj.target_id:
            sg_ids = db_api._get_sgs_attached_to_port(context,
                                                      log_obj.target_id)
            for sg_id in sg_ids:
                try:
                    pg = self.ovn_nb.lookup("Port_Group",
                                            utils.ovn_port_group_name(sg_id))
                    pgs.append({"name": pg.name,
                                "external_ids": pg.external_ids,
                                "acls": [r.uuid for r in pg.acls]})
                except idlutils.RowNotFound:
                    pass
        return pgs

    def _create_sg_drop_acls(self, context, log_obj, ovn_txn, log_name):
        """Create per-SG drop ACLs for network log attribution.

        When logging DROP events for a specific security group, we create
        drop ACLs on the SG's port group at a higher priority than the
        global neutron_pg_drop. This ensures drop events are correctly
        attributed to the specific security group's log resource.
        """
        if log_obj.event not in DROP_LOG_EVENTS:
            return
        if is_flow_sample_log(log_obj):
            # The sampling reconciliation creates the drop ACLs of a
            # flow-sample log without enabling packet logging.
            return
        sg_pgs = self._get_sg_port_groups(context, log_obj)
        for pg in sg_pgs:
            for acl in acl_utils.add_acls_for_log_drop_port_group(
                    pg["name"], log_name, self.meter_name):
                ovn_txn.add(self.ovn_nb.pg_acl_add(**acl, may_exist=True))

    def _remove_sg_drop_acls(self, context, log_obj, ovn_txn):
        """Remove per-SG drop ACLs created for network log attribution.

        The drop ACLs of a security group are shared by both network log
        outputs. They are kept while an enabled flow-sample log still
        observes the drops of that security group; the packet logging
        columns of those ACLs are cleared separately.
        """
        sg_pgs = self._get_sg_port_groups(context, log_obj)
        for pg in sg_pgs:
            sg_id = pg["external_ids"].get(ovn_const.OVN_SG_EXT_ID_KEY)
            if sg_id and self._get_flow_sample_logs(
                    context, enabled=True, resource_id=sg_id,
                    event=list(DROP_LOG_EVENTS)):
                LOG.debug("Keeping drop ACLs of Port Group %s for its "
                          "flow-sample network logs", pg["name"])
                continue
            for direction, p in (('from-lport', 'inport'),
                                 ('to-lport', 'outport')):
                ovn_txn.add(self.ovn_nb.pg_acl_del(
                    pg["name"], direction,
                    ovn_const.ACL_PRIORITY_LOG_DROP,
                    f'{p} == @{pg["name"]} && ip'))

    def _get_other_sg_drop_logs(self, context, log_obj):
        """Get other enabled logs that still need per-SG drop ACLs."""
        filters = {'enabled': True, 'event': list(DROP_LOG_EVENTS)}
        log_objs = []
        if log_obj.resource_id:
            log_objs.extend(self._get_logs(
                context, resource_id=log_obj.resource_id, **filters))
            port_ids = db_api._get_ports_attached_to_sg(context,
                                                        log_obj.resource_id)
            if port_ids:
                log_objs.extend(self._get_logs(
                    context, target_id=port_ids, **filters))
        elif log_obj.target_id:
            log_objs.extend(self._get_logs(
                context, target_id=log_obj.target_id, **filters))
            sg_ids = db_api._get_sgs_attached_to_port(context,
                                                      log_obj.target_id)
            if sg_ids:
                log_objs.extend(self._get_logs(
                    context, resource_id=sg_ids, **filters))
        else:
            return []

        other_logs = {}
        for log in log_objs:
            if log.id != log_obj.id:
                other_logs[log.id] = log
        return list(other_logs.values())

    def create_log(self, context, log_obj):
        """Create a log_obj invocation.

        :param context: current running context information
        :param log_obj: a log objects being created
        """
        LOG.debug("Create_log %s", log_obj)

        if is_flow_sample_log(log_obj):
            self._check_flow_sample_log(log_obj)
            self._sync_sg_sampling(context, [log_obj.resource_id],
                                   strict=True)
            return

        pgs = self._pgs_from_log_obj(context, log_obj)
        actions_enabled = self._acl_actions_enabled(log_obj)
        log_name = utils.ovn_name(log_obj.id)
        with self.ovn_nb.transaction(check_error=True) as ovn_txn:
            self._ovn_client.create_ovn_fair_meter(self.meter_name,
                                                   txn=ovn_txn)
            self._set_acls_log(pgs, context, ovn_txn, actions_enabled,
                               log_name)
            self._create_sg_drop_acls(context, log_obj, ovn_txn, log_name)

    def create_log_precommit(self, context, log_obj):
        """Create a log_obj precommit.

        :param context: current running context information
        :param log_obj: a log object being created
        """
        LOG.debug("Create_log_precommit %s", log_obj)

    def _unset_disabled_acls(self, context, log_obj, ovn_txn):
        """Check if we need to disable any ACLs after an update.

        Will return True if there were more logs, and False if there was
        nothing to check.

        :param context: current running context information
        :param log_obj: a log_object which was updated
        :returns: True if there were other logs enabled, otherwise False.
        """
        if log_obj.enabled:
            return False

        pgs = self._pgs_from_log_obj(context, log_obj)
        other_logs = [log for log in self._get_packet_logs(context)
                      if log.id != log_obj.id and log.enabled]
        if not other_logs:
            return False

        if log_obj.event == log_const.ALL_EVENT:
            acls_to_check = pgs[0]["acls"].copy()
            if not acls_to_check:
                return True
            for log in other_logs:
                for acl in self._pgs_from_log_obj(context, log)[0]["acls"]:
                    if acl in acls_to_check:
                        acls_to_check.remove(acl)
                    if not acls_to_check:
                        return True
            acls_to_remove = [{"name": pgs[0]["name"], "acls": acls_to_check}]
            self._remove_acls_log(acls_to_remove, ovn_txn)
        else:
            all_events = {log.event for log in other_logs
                          if (not log.resource_id or
                              log.resource_id == log_obj.resource_id)}
            if (log_const.ALL_EVENT not in all_events and
                    log_obj.event not in all_events):
                self._remove_acls_log(pgs, ovn_txn,
                                      utils.ovn_name(log_obj.id))
        return True

    def update_log(self, context, log_obj):
        """Update a log_obj invocation.

        :param context: current running context information
        :param log_obj: a log object being updated

        """
        LOG.debug("Update_log %s", log_obj)

        if is_flow_sample_log(log_obj):
            if log_obj.enabled:
                if not log_obj.resource_id or log_obj.target_id:
                    raise log_exc.FlowSampleSelectorNotSupported()
                # The logging plugin validates a disabled log that is being
                # enabled. An update of a log that was already enabled, for
                # example one repeating enabled=True, converges to what can
                # be applied now and detaches the sampling if it is no
                # longer available.
                available = self._flow_sampling_available()
                self._sync_sg_sampling(context, [log_obj.resource_id],
                                       strict=available)
            else:
                self._sync_sg_sampling(context, [log_obj.resource_id],
                                       remove_unused_drop_acls_for=log_obj)
            return

        log_name = utils.ovn_name(log_obj.id)
        with self.ovn_nb.transaction(check_error=True) as ovn_txn:

            if not self._unset_disabled_acls(context, log_obj, ovn_txn):
                pgs = self._pgs_from_log_obj(context, log_obj)
                actions_enabled = self._acl_actions_enabled(log_obj)
                self._set_acls_log(pgs, context, ovn_txn, actions_enabled,
                                   log_name)
            if log_obj.enabled:
                self._create_sg_drop_acls(context, log_obj, ovn_txn,
                                          log_name)
            elif log_obj.event in (log_const.DROP_EVENT, log_const.ALL_EVENT):
                other_sg_drop_logs = self._get_other_sg_drop_logs(context,
                                                                  log_obj)
                self._remove_sg_drop_acls(context, log_obj, ovn_txn)
                for log in other_sg_drop_logs:
                    self._create_sg_drop_acls(context, log, ovn_txn,
                                              utils.ovn_name(log.id))
        self._resync_sampled_sgs(
            context, self._sampling_sg_ids_for_log(context, log_obj))

    def delete_log(self, context, log_obj):
        """Delete a log_obj invocation.

        :param context: current running context information
        :param log_obj: a log_object being deleted

        """
        LOG.debug("Delete_log %s", log_obj)

        if is_flow_sample_log(log_obj):
            self._sync_sg_sampling(context, [log_obj.resource_id],
                                   remove_unused_drop_acls_for=log_obj)
            return

        sampling_sg_ids = self._sampling_sg_ids_for_log(context, log_obj)
        try:
            self._delete_packet_log(context, log_obj)
        finally:
            self._resync_sampled_sgs(context, sampling_sg_ids)

    def _delete_packet_log(self, context, log_obj):
        # If we are removing the last log_obj, let's clear log from all acls.
        # This is a simple way of ensuring that no acl logs are left behind!
        log_objs = self._get_packet_logs(context)
        if not log_objs or (
                len(log_objs) == 1 and log_objs[0].id == log_obj.id):
            pgs = self._pgs_all()
            with self.ovn_nb.transaction(check_error=True) as ovn_txn:
                self._remove_acls_log(pgs, ovn_txn)
                self._remove_sg_drop_acls(context, log_obj, ovn_txn)
                ovn_txn.add(self.ovn_nb.meter_del(self.meter_name,
                                                  if_exists=True))
                ovn_txn.add(self.ovn_nb.meter_del(
                    self.meter_name + "_stateless", if_exists=True))
            LOG.info("All ACL logs cleared after deletion of log_obj %s",
                     log_obj.id)
            return

        # Remove log_obj and revisit all remaining ones, since the acls that
        # were serving the removed log_obj may be usable by the remaining
        # log_objs.
        pgs = self._pgs_from_log_obj(context, log_obj)
        with self.ovn_nb.transaction(check_error=True) as ovn_txn:
            self._remove_acls_log(pgs, ovn_txn, utils.ovn_name(log_obj.id))
            self._remove_sg_drop_acls(context, log_obj, ovn_txn)

        # TODO(flaviof): We needed to break this second part into a separate
        # transaction because logic that determines the value of the 'freed up'
        # acl rows will not see the modified rows unless it was inside an an
        # idl command.
        with self.ovn_nb.transaction(check_error=True) as ovn_txn:
            self._update_log_objs(context, ovn_txn, [lo for lo in log_objs
                                                     if lo.id != log_obj.id])

    def resource_update(self, context, log_objs):
        """Tell the agent when resources related to log_objects are
        being updated

        :param context: current running context information
        :param log_objs: a list of log_objects, whose related resources are
                         being updated.
        """
        LOG.debug("Resource_update %s", log_objs)

        packet_logs = [lo for lo in log_objs if not is_flow_sample_log(lo)]
        if packet_logs:
            with self.ovn_nb.transaction(check_error=True) as ovn_txn:
                self._update_log_objs(context, ovn_txn, packet_logs)
        sg_ids = set()
        for log_obj in log_objs:
            sg_ids.update(self._sampling_sg_ids_for_log(context, log_obj))
        self._resync_sampled_sgs(context, sg_ids)

    def _get_sampling_config(self):
        """Return the sampling configuration, or None if disabled."""
        try:
            return ovn_sampling.SamplingConfig.from_conf(
                cfg.CONF.network_log)
        except ValueError as exc:
            LOG.error("Invalid OVN ACL sampling configuration: %s", exc)
            return None

    def _sampling_schema_supported(self):
        return all(self.ovn_nb.is_col_present(table, column)
                   for table, column in ovn_sampling.REQUIRED_COLUMNS)

    def _flow_sampling_available(self):
        return (self._get_sampling_config() is not None and
                self._sampling_schema_supported())

    def _check_flow_sampling_available(self):
        if not self._flow_sampling_available():
            raise FlowSamplingNotAvailable()

    def _check_flow_sample_log(self, log_obj):
        """Validate a flow-sample log before applying it.

        The logging plugin validates requests before they reach the
        driver; this check guards the driver against logs stored by a
        server without that validation.
        """
        if not log_obj.resource_id or log_obj.target_id:
            raise log_exc.FlowSampleSelectorNotSupported()
        self._check_flow_sampling_available()

    def reconcile_sampling(self, context, sg_ids=None, periodic=False):
        """Converge the sampling of security groups with flow-sample logs.

        Used by the maintenance task and the OVN DB sync tool to repair
        references lost to ACL replacement, missed notifications or
        failed transactions, to detach the sampling of logs that remain
        enabled after the operator disabled it, and to remove the sampling
        left on security groups whose logs no longer exist.

        :param sg_ids: the security groups to reconcile; if not given, all
            the security groups selected by a flow-sample log and all those
            whose Port Group still carries Neutron sampling state.
        :param periodic: report the ACL references that are not managed by
            Neutron at debug level, since a periodic caller would repeat
            the report at every run.
        :returns: the list of reconciled security group IDs.
        """
        if (self._log_plugin is None or
                not self._sampling_schema_supported()):
            return []
        if sg_ids is None:
            sg_ids = {lo.resource_id for lo in
                      self._get_flow_sample_logs(context.elevated())
                      if lo.resource_id}
            sg_ids |= self._sg_ids_with_sampling_state()
        sg_ids = sorted(sg_ids)
        if sg_ids:
            self._sync_sg_sampling(context, sg_ids, prune_drop_acls=True,
                                   quiet_conflicts=periodic)
        return sg_ids

    @staticmethod
    def _is_unlogged_drop_acl(acl):
        """Return True for a per-SG drop ACL without packet logging.

        Such an ACL is created for the drops of a flow-sample log; a packet
        log enables the logging of the drop ACLs it requires.
        """
        return (acl.priority == ovn_const.ACL_PRIORITY_LOG_DROP and
                acl.action == ovn_const.ACL_ACTION_DROP and
                not acl.log)

    def _sg_ids_with_sampling_state(self):
        """Return the security groups whose Port Group carries sampling.

        A Port Group carries Neutron sampling state when one of its ACLs
        has a Sample metadata recorded by Neutron or is a per-SG drop ACL
        without packet logging.
        """
        sg_ids = set()
        for pg in self.ovn_nb.db_list_rows('Port_Group').execute(
                check_error=True):
            sg_id = pg.external_ids.get(ovn_const.OVN_SG_EXT_ID_KEY)
            if sg_id and any(
                    self._is_unlogged_drop_acl(acl) or
                    any(ovn_sampling.recorded_metadata(acl, stage)
                        for stage in ovn_sampling.STAGES)
                    for acl in pg.acls):
                sg_ids.add(sg_id)
        return sg_ids

    def sync_security_group_sampling(self, context, sg_id, txn):
        """Reapply the sampling of a security group whose ACLs changed.

        Called by the ML2/OVN mechanism driver inside the transaction that
        replaces the rule ACLs of a security group, so that the new ACLs
        reference the Samples required by the enabled flow-sample logs.
        """
        self._sync_sg_sampling(context, [sg_id], only_if_sampled=True,
                               txn=txn)

    def resync_security_group_sampling(self, context, sg_id):
        """Check the sampling of a security group after a transaction.

        Called by the ML2/OVN mechanism driver after the transaction in
        which sync_security_group_sampling added the sampling of the
        replaced ACLs has committed. The IDL retries a conflicting
        transaction with the commands built from the logs read before, so
        the sampling is converged again from the stored logs, in a
        transaction of its own that checks them once more after it
        commits. A failure is logged rather than raised.
        """
        try:
            self._sync_sg_sampling(context, [sg_id])
        except Exception:
            LOG.exception("Failed to reapply OVN ACL sampling for security "
                          "group %s", sg_id)

    def _sampling_sg_ids_for_log(self, context, log_obj):
        """Return the security groups whose ACLs a log object can modify."""
        if log_obj.resource_id:
            return [log_obj.resource_id]
        if log_obj.target_id:
            return db_api._get_sgs_attached_to_port(context,
                                                    log_obj.target_id)
        return []

    def _resync_sampled_sgs(self, context, sg_ids):
        """Reapply sampling after changes that can replace sampled ACLs.

        Used after packet logging and security group rule changes. A
        failure is logged rather than raised: the triggering change has
        already been committed and must not be reported as failed because
        of the sampling output of other logs.
        """
        try:
            self._sync_sg_sampling(context, sg_ids, only_if_sampled=True)
        except Exception:
            LOG.exception("Failed to reapply OVN ACL sampling for security "
                          "groups %s", sorted(sg_ids))

    def _sync_sg_sampling(self, context, sg_ids, only_if_sampled=False,
                          remove_unused_drop_acls_for=None, strict=False,
                          txn=None, prune_drop_acls=False,
                          quiet_conflicts=False):
        """Converge the OVN ACL sampling of security groups.

        The desired state of each security group is the union of its
        enabled flow-sample logs. It is computed from the stored logs, so
        the same call serves log changes, ACL replacement and recovery.

        :param sg_ids: the security groups to reconcile.
        :param only_if_sampled: skip the security groups without a
            flow-sample log; used after packet logging changes that may
            recreate sampled ACLs.
        :param remove_unused_drop_acls_for: a disabled or deleted
            flow-sample log; its per-SG drop ACLs without packet logging are
            removed if no other enabled log, of either output, still
            requires them. An ACL that references a Sample not managed by
            Neutron is kept.
        :param strict: fail with a conflict instead of a warning when a
            required ACL reference is not managed by Neutron; used for API
            requests that enable sampling.
        :param txn: an open Northbound transaction to add the commands to.
            When given, the caller commits it and conflicts are not
            reported.
        :param prune_drop_acls: remove the per-SG drop ACLs without packet
            logging that no enabled log, of either output, requires; used
            by the reconciliation.
        :param quiet_conflicts: report the ACL references that are not
            managed by Neutron at debug level instead of warning.
        """
        sg_ids = sorted({sg_id for sg_id in sg_ids if sg_id})
        if not sg_ids or not self._sampling_schema_supported():
            return
        # The ML2/OVN driver registers this driver even when the logging
        # service plugin is not loaded; there are no logs to apply then.
        if self._log_plugin is None:
            return
        # Flow-sample logs are administrative and may belong to another
        # project than the one whose request changed the ACLs.
        context = context.elevated()
        config = self._get_sampling_config()
        flow_logs = self._get_flow_sample_logs(context, resource_id=sg_ids)
        if only_if_sampled:
            sampled = {lo.resource_id for lo in flow_logs}
            sg_ids = [sg_id for sg_id in sg_ids if sg_id in sampled]
            if not sg_ids:
                return

        def plan(flow_logs):
            return self._sampling_plan(context, sg_ids, config, flow_logs,
                                       remove_unused_drop_acls_for,
                                       prune_drop_acls)

        plans = [plan(flow_logs)]
        applied = []

        def add_commands(ovn_txn):
            # A retried transaction recomputes the desired state from the
            # stored logs, which can have changed in the meantime.
            if plans:
                current = plans.pop()
            else:
                current = plan(self._get_flow_sample_logs(
                    context, resource_id=sg_ids))
            applied.append(current)
            actions_by_sg, drop_acls_needed, prunable = current
            set_cmds = {}
            if any(actions_by_sg.values()):
                ovn_txn.add(self.ovn_nb.ensure_acl_sampling_resources(config))
            for sg_id in sg_ids:
                pg_name = utils.ovn_port_group_name(sg_id)
                pg = self.ovn_nb.lookup('Port_Group', pg_name, default=None)
                if pg is None:
                    LOG.info("Port Group %s not found, skipping its ACL "
                             "sampling", pg_name)
                    continue
                if sg_id in drop_acls_needed:
                    for acl in acl_utils.add_acls_for_sampling_drop_port_group(
                            pg_name):
                        ovn_txn.add(self.ovn_nb.pg_acl_add(**acl,
                                                           may_exist=True))
                set_cmds[sg_id] = ovn_txn.add(
                    self.ovn_nb.set_port_group_acl_sampling(
                        pg_name, actions_by_sg[sg_id],
                        config.collector_id if config else None,
                        raise_on_conflict=strict,
                        remove_unlogged_drop_acls=sg_id in prunable))
            return set_cmds

        if txn is not None:
            add_commands(txn)
            return
        set_cmds = self._commit_sampling(add_commands)
        # The IDL retries a transaction that conflicts with a concurrent
        # Northbound change by running the same commands, which carry the
        # logs read before. Another server can have changed the logs and
        # their sampling meanwhile, so check the stored logs again and
        # converge once more if they no longer match what was applied.
        for _recheck in range(SAMPLING_RECHECKS):
            fresh = plan(self._get_flow_sample_logs(
                context, resource_id=sg_ids))
            if self._plan_key(fresh) == self._plan_key(applied[-1]):
                break
            LOG.debug("The flow-sample logs of security groups %s changed "
                      "while their sampling was applied, applying it again",
                      sg_ids)
            plans.append(fresh)
            set_cmds = self._commit_sampling(add_commands)

        report = LOG.debug if quiet_conflicts else LOG.warning
        for sg_id, cmd in set_cmds.items():
            result = getattr(cmd, 'result', None)
            if isinstance(result, dict) and result.get('conflicts'):
                report("Security group %(sg)s has ACL sample references "
                       "that are not managed by Neutron and were left "
                       "unchanged: %(conflicts)s",
                       {'sg': sg_id, 'conflicts': result['conflicts']})

    @staticmethod
    def _plan_key(plan):
        """Return the part of a sampling plan that determines its result."""
        actions_by_sg, drop_acls_needed, prunable = plan
        return ({sg_id: frozenset(actions)
                 for sg_id, actions in actions_by_sg.items() if actions},
                frozenset(drop_acls_needed), frozenset(prunable))

    def _sampling_plan(self, context, sg_ids, config, flow_logs, removed_log,
                       prune_drop_acls):
        """Compute the desired sampling state of security groups.

        :returns: a tuple of the sampled ACL actions of each security
            group, the security groups that need drop ACLs for sampling,
            and the security groups whose drop ACLs without packet logging
            are to be removed. They are removed for the security group of
            a disabled or deleted DROP or ALL log, and for every security
            group with ``prune_drop_acls``, when no enabled log of either
            output requires them.
        """
        actions_by_sg = collections.defaultdict(set)
        drop_acls_needed = set()
        if config is not None:
            for lo in flow_logs:
                if not lo.enabled:
                    continue
                actions_by_sg[lo.resource_id] |= self._acl_actions_enabled(lo)
                if lo.event in DROP_LOG_EVENTS:
                    drop_acls_needed.add(lo.resource_id)

        prunable = set()
        if (removed_log is not None and
                removed_log.event in DROP_LOG_EVENTS and
                removed_log.resource_id not in drop_acls_needed and
                not self._get_other_sg_drop_logs(context, removed_log)):
            prunable.add(removed_log.resource_id)
        if prune_drop_acls:
            for sg_id in sg_ids:
                if sg_id in drop_acls_needed or sg_id in prunable:
                    continue
                selector = self._log_dict_to_obj(
                    {'id': None, 'resource_id': sg_id, 'target_id': None})
                if not any(not is_flow_sample_log(lo) for lo in
                           self._get_other_sg_drop_logs(context, selector)):
                    prunable.add(sg_id)
        return actions_by_sg, drop_acls_needed, prunable

    def _commit_sampling(self, add_commands):
        """Commit sampling commands, retrying a Sample identifier race.

        Sample metadata values are chosen from the rows visible to this
        server. Another server can insert the same value first, which the
        Northbound index rejects; the next attempt sees the new row.
        """
        for attempt in range(1, SAMPLING_TXN_ATTEMPTS + 1):
            try:
                with self.ovn_nb.transaction(check_error=True) as ovn_txn:
                    result = add_commands(ovn_txn)
                return result
            except RuntimeError as exc:
                if ('constraint violation' not in str(exc) or
                        attempt == SAMPLING_TXN_ATTEMPTS):
                    raise
                LOG.info("Retrying OVN ACL sampling transaction after a "
                         "constraint violation (attempt %d): %s",
                         attempt, exc)

    def add_logging_options_to_acls(self, neutron_acls, context):
        log_objs = self._get_packet_logs(context)
        for log_obj in log_objs:
            pgs = self._pgs_from_log_obj(context, log_obj)
            actions_enabled = self._acl_actions_enabled(log_obj)
            self._set_neutron_acls_log(pgs, context, actions_enabled,
                                       utils.ovn_name(log_obj.id),
                                       neutron_acls)

    # This function is a version of set_acls_log meant to change neutron
    # defined acls, mostly thought for ovndbsync consistency check.
    def _set_neutron_acls_log(self, pgs, context, actions_enabled, log_name,
                              neutron_acls):
        acl_changes, acl_visits = 0, 0
        for pg in pgs:
            meter_name = self.meter_name
            if pg['name'] != ovn_const.OVN_DROP_PORT_GROUP_NAME:
                if ovn_const.OVN_SG_EXT_ID_KEY not in pg["external_ids"]:
                    LOG.info("Port Group %s is not part of any security "
                             "group, skipping its network log "
                             "setting...", pg["name"])
                    continue
                sg_id = pg['external_ids'][ovn_const.OVN_SG_EXT_ID_KEY]
                sg_stateful = sg_obj.SecurityGroup.get_sgs_stateful_flag(
                    context, [sg_id])
                if sg_id not in sg_stateful:
                    LOG.warning("Port Group %s is missing a corresponding "
                                "security group, skipping its network log "
                                "setting...", pg["name"])
                    continue
                if not sg_stateful[sg_id]:
                    meter_name = meter_name + ("_stateless")
            # We need to get the OVN ACL because UUID is not listed as a
            # property on neutron defined ACLs (and it shouldn't), so we need
            # to check which ACL is that UUID referring to, using match as
            # differentiating value.
            for acl in neutron_acls:
                acl_visits += 1
                # skip acls used by a different network log
                n_acl_name = acl['name']
                if n_acl_name and n_acl_name != log_name:
                    continue
                # Don't claim ACLs whose action is not relevant
                if not n_acl_name and acl['action'] not in actions_enabled:
                    continue
                action = acl['action'] in actions_enabled
                acl['log'] = action
                acl['meter'] = meter_name
                acl['name'] = log_name
                acl['severity'] = "info"
                if acl.get('options'):
                    acl["options"] = {'log-related': "true"}
                # label is not set because the actual number should not
                # be compared or taken into account, we only need it to be
                # different from 0.
                acl_changes += 1
        LOG.info("Set %d (out of %d visited) Neutron ACLs for network log %s",
                 acl_changes, acl_visits, log_name)

    def _get_all_log_pgs(self, ctx):
        """Get all Port Group names associated to a Log Object.

        :param log_plugin: Currently loaded log_plugging.
        :param ctx: current running context information
        """
        log_objs = self._get_packet_logs(ctx)
        log_pgs = []
        for log_obj in log_objs:
            log_pgs.extend(self._pgs_from_log_obj(ctx, log_obj))
        return log_pgs

    def add_label_related(self, n_acl, ctx):
        # Get acls to be able to check if label is present in OVN ACLs and
        # also check old label value for ACL if it was already present.
        acls = [acl for pg in self._get_all_log_pgs(ctx) for acl in pg["acls"]]
        if not acls:
            return
        acl = self.ovn_nb.lookup("ACL", acls[0], default=None)
        if not hasattr(acl, 'label'):
            return
        n_acl["label"] = secrets.SystemRandom().randrange(1, MAX_INT_LABEL)
        n_acl["options"] = {'log-related': 'true'}


def register(plugin_driver):
    """Register the driver."""
    global DRIVER
    if not DRIVER:
        DRIVER = OVNDriver.create(plugin_driver)

    # Trigger decorator
    importutils.import_module(
        "neutron.services.logapi.common.sg_validate"
    )
    # Register resource callback handler
    manager.register(
        resources.SECURITY_GROUP_RULE, sg_callback.SecurityGroupRuleCallBack)

    LOG.info("OVN logging driver registered")
    return DRIVER
