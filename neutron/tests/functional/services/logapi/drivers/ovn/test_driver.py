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
from neutron_lib import constants as n_const
from neutron_lib import context
from neutron_lib import exceptions as n_exc
from neutron_lib.services.logapi import constants as log_const
from oslo_config import cfg

from neutron.common.ovn import constants as ovn_const
from neutron.common.ovn import sampling as ovn_sampling
from neutron.common.ovn import utils
from neutron.services.logapi.common import exceptions as log_exc
from neutron.tests.functional import base as functional_base


class LogApiTestCaseBase(functional_base.TestOVNFunctionalBase):
    def setUp(self):
        super().setUp()
        self.log_driver = self.mech_driver.log_driver
        self.ctxt = context.Context('admin', self._project_id)

    def _log_data(self, sg_id=None, port_id=None, enabled=True):
        log_data = {'project_id': self.ctxt.project_id,
                    'resource_type': 'security_group',
                    'description': 'test net log',
                    'name': 'logme',
                    'enabled': enabled,
                    'event': log_const.ALL_EVENT}
        if sg_id:
            log_data['resource_id'] = sg_id
        if port_id:
            log_data['target_id'] = port_id
        return {'log': log_data}


class LogApiTestCaseSimple(LogApiTestCaseBase):
    def test_basic_get(self):
        log_obj = self.log_plugin.create_log(self.ctxt, self._log_data())
        self.assertIsNotNone(log_obj)
        log_obj_get = self.log_plugin.get_log(self.ctxt, log_obj['id'])
        self.assertEqual(log_obj, log_obj_get)
        log_obj2 = self.log_plugin.create_log(self.ctxt, self._log_data())
        self.assertIsNotNone(log_obj2)
        log_objs_get = self.log_plugin.get_logs(self.ctxt)
        log_objs_ids = {x['id'] for x in log_objs_get}
        self.assertEqual({log_obj['id'], log_obj2['id']}, log_objs_ids)


class LogApiTestCaseComplex(LogApiTestCaseBase):
    def setUp(self):
        super().setUp()
        self._prepare_env()

    def _prepare_env(self):
        self.net = self._create_network(
            self.fmt, 'private', admin_state_up=True).json['network']['id']
        self.subnet = self._create_subnet(
            self.fmt, self.net, '10.0.0.0/24', enable_dhcp=False).json[
            'subnet']['id']

        self.sg1 = self._create_security_group('test_sg1_ssh')
        self.sg2 = self._create_security_group('test_sg2_http')
        self.sg3 = self._create_security_group('test_sg3_telnet_ssh')
        self.sg1rs = [self._create_security_group_rule(self.sg1, 22)]
        self.sg2rs = [self._create_security_group_rule(self.sg2, 80)]
        self.sg3rs = [self._create_security_group_rule(self.sg3, 23),
                      self._create_security_group_rule(self.sg3, 22)]
        self.sgs = [self.sg1, self.sg2, self.sg3]
        self.sgrs = self.sg1rs + self.sg2rs + self.sg3rs

        self.port1_sgs = [self.sg1]
        self.port1_sgrs = self.sg1rs
        self.port1 = self._create_port(self.fmt, self.net,
                                       security_groups=self.port1_sgs)
        self.port2_sgs = [self.sg2, self.sg3]
        self.port2_sgrs = self.sg2rs + self.sg3rs
        self.port2 = self._create_port(self.fmt, self.net,
                                       security_groups=self.port2_sgs)
        self.port3_sgs = [self.sg1, self.sg3]
        self.port3_sgrs = self.sg1rs + self.sg3rs
        self.port3 = self._create_port(self.fmt, self.net,
                                       security_groups=self.port3_sgs)

    def _create_port(self, name, net_id, security_groups):
        data = {'port': {'name': name,
                         'network_id': net_id,
                         'security_groups': security_groups}}
        req = self.new_create_request('ports', data, self.fmt)
        res = req.get_response(self.api)
        return self.deserialize(self.fmt, res)['port']['id']

    def _create_security_group(self, name):
        data = {'security_group': {'name': name}}
        req = self.new_create_request('security-groups', data, self.fmt)
        res = req.get_response(self.api)
        return self.deserialize(self.fmt, res)['security_group']['id']

    def _create_security_group_rule(self, sg_id, tcp_port):
        data = {'security_group_rule': {'security_group_id': sg_id,
                                        'direction': 'ingress',
                                        'protocol': n_const.PROTO_NAME_TCP,
                                        'ethertype': n_const.IPv4,
                                        'port_range_min': tcp_port,
                                        'port_range_max': tcp_port}}
        req = self.new_create_request('security-group-rules', data, self.fmt)
        res = req.get_response(self.api)
        return self.deserialize(self.fmt, res)['security_group_rule']['id']

    def _find_security_group_row_by_id(self, sg_id):
        for row in self.nb_api._tables['Port_Group'].rows.values():
            if row.name == utils.ovn_port_group_name(sg_id):
                return row

    def _find_security_group_rule_row_by_id(self, sgr_id):
        for row in self.nb_api._tables['ACL'].rows.values():
            if (row.external_ids.get(
                    ovn_const.OVN_SG_RULE_EXT_ID_KEY) == sgr_id):
                return row

    def _check_acl_log(self, sgr, is_enabled=True):
        acl = self._find_security_group_rule_row_by_id(sgr)
        self.assertIsNotNone(acl)
        self.assertEqual(is_enabled, acl.log)
        # Here we compare if there is a name because the log can be
        # disabled but disabling a log would not take out the properties
        # attached to it.
        if acl.name:
            self.assertNotEqual(0, acl.label)
            self.assertEqual("true", acl.options.get("log-related"))
        else:
            self.assertEqual(0, acl.label)
            self.assertIsNone(acl.options.get("log-related"))
        return acl

    def _check_acl_log_drop(self, is_enabled=True):
        acls = self.nb_api.get_port_group(
            ovn_const.OVN_DROP_PORT_GROUP_NAME).acls
        self.assertTrue(acls)
        for acl in acls:
            self.assertEqual(is_enabled, acl.log)

    def _check_sg_drop_acls(self, sg_id, is_enabled=True):
        """Check per-SG drop ACLs at LOG_DROP priority on the SG port group."""
        pg = self.nb_api.get_port_group(utils.ovn_port_group_name(sg_id))
        drop_acls = [acl for acl in pg.acls
                     if acl.priority == ovn_const.ACL_PRIORITY_LOG_DROP and
                     acl.action == ovn_const.ACL_ACTION_DROP]
        if is_enabled:
            self.assertTrue(drop_acls,
                            "Expected per-SG drop ACLs but found none")
            for acl in drop_acls:
                self.assertTrue(acl.log)
        else:
            self.assertEqual([], drop_acls)

    def _check_sgrs(self, sgrs=None, is_enabled=True):
        if not sgrs:
            sgrs = self.sgrs
        for sgr in sgrs:
            self._check_acl_log(sgr, is_enabled)

    def test_add_and_remove(self):
        self._check_sgrs(is_enabled=False)
        self.assertEqual([],
                         self.nb_api.meter_list().execute(check_error=True))

        log_obj = self.log_plugin.create_log(self.ctxt, self._log_data())
        for sgr in self.sgrs:
            acl = self._check_acl_log(sgr)
            self.assertEqual(utils.ovn_name(log_obj['id']), acl.name[0])
            meter = self.nb_api.meter_get(acl.meter[0]).execute(
                check_error=True)
            self.assertEqual([True], meter.fair)
            self.assertEqual('pktps', meter.unit)
            self.assertEqual(1, len(meter.bands))
            self.assertEqual({ovn_const.OVN_DEVICE_OWNER_EXT_ID_KEY:
                              log_const.LOGGING_PLUGIN}, meter.external_ids)

        self.log_plugin.delete_log(self.ctxt, log_obj['id'])
        self._check_sgrs(is_enabled=False)
        self.assertEqual([],
                         self.nb_api.meter_list().execute(check_error=True))

        log_objs = []
        for sg in self.sgs:
            log_data = self._log_data(sg_id=sg)
            log_objs.append(self.log_plugin.create_log(self.ctxt, log_data))
        self.assertEqual(len(log_objs),
                         len(self.log_plugin.get_logs(self.ctxt)))
        self._check_sgrs(is_enabled=True)

        # Attempt to delete non-existing row
        self.assertRaises(log_exc.LogResourceNotFound,
                          self.log_plugin.delete_log,
                          self.ctxt, log_obj['id'])

        self.log_plugin.delete_log(self.ctxt, log_objs[1]['id'])
        self._check_sgrs(sgrs=self.sg1rs, is_enabled=True)
        self._check_sgrs(sgrs=self.sg2rs, is_enabled=False)
        self._check_sgrs(sgrs=self.sg3rs, is_enabled=True)

        self.log_plugin.delete_log(self.ctxt, log_objs[2]['id'])
        self._check_sgrs(sgrs=self.sg1rs, is_enabled=True)
        self._check_sgrs(sgrs=self.sg2rs, is_enabled=False)
        self._check_sgrs(sgrs=self.sg3rs, is_enabled=False)

        self.log_plugin.delete_log(self.ctxt, log_objs[0]['id'])
        self.assertEqual([], self.log_plugin.get_logs(self.ctxt))
        self._check_sgrs(is_enabled=False)

        # Attempt to delete from empty table
        self.assertRaises(log_exc.LogResourceNotFound,
                          self.log_plugin.delete_log,
                          self.ctxt, log_objs[0]['id'])

    def test_update_all(self):
        # Note: only these fields are supported for update:
        # openstack network log set [-h] [--description <description>]
        # [--enable | --disable] [--name <name>] <network-log>

        log_data = self._log_data()
        log_obj = self.log_plugin.create_log(self.ctxt, log_data)
        self._check_sgrs()

        log_data['log']['name'] = 'logme-nay'
        log_data['log']['enabled'] = False
        self.log_plugin.update_log(self.ctxt, log_obj['id'], log_data)
        self._check_sgrs(is_enabled=False)

        log_data['log']['name'] = 'logme-yay'
        log_data['log']['description'] = 'logs are a beautiful thing'
        log_data['log']['enabled'] = True
        self.log_plugin.update_log(self.ctxt, log_obj['id'], log_data)
        self._check_sgrs()

    def test_update_one_sg(self):
        log_data = self._log_data(sg_id=self.sg2, enabled=False)
        log_obj = self.log_plugin.create_log(self.ctxt, log_data)
        self._check_sgrs(is_enabled=False)

        log_data['log']['enabled'] = True
        self.log_plugin.update_log(self.ctxt, log_obj['id'], log_data)
        self._check_sgrs(sgrs=self.sg1rs, is_enabled=False)
        self._check_sgrs(sgrs=self.sg2rs, is_enabled=True)
        self._check_sgrs(sgrs=self.sg3rs, is_enabled=False)

    def test_overlap_net_logs(self):
        log_data1 = self._log_data(sg_id=self.sg3, port_id=self.port3)
        log_obj1 = self.log_plugin.create_log(self.ctxt, log_data1)
        self._check_sgrs(sgrs=self.sg1rs, is_enabled=False)
        self._check_sgrs(sgrs=self.sg2rs, is_enabled=False)
        self._check_sgrs(sgrs=self.sg3rs, is_enabled=True)

        log_data2 = self._log_data(port_id=self.port2)
        log_obj2 = self.log_plugin.create_log(self.ctxt, log_data2)
        self._check_sgrs(sgrs=self.sg1rs, is_enabled=False)

        # port 2 uses sg2 and sg3. However, sg3 is in use by log_obj1
        # so only acls for 2 would be associated with log_obj2
        for sgr in self.sg2rs:
            acl = self._check_acl_log(sgr)
            self.assertEqual(utils.ovn_name(log_obj2['id']), acl.name[0])
        for sgr in self.sg3rs:
            acl = self._check_acl_log(sgr)
            self.assertEqual(utils.ovn_name(log_obj1['id']), acl.name[0])

        # Next, delete log_obj1 and make sure that lob_obj2 gets to
        # claim what it could not use before
        self.log_plugin.delete_log(self.ctxt, log_obj1['id'])
        self._check_sgrs(sgrs=self.sg1rs, is_enabled=False)
        for sgr in self.sg2rs + self.sg3rs:
            acl = self._check_acl_log(sgr)
            self.assertEqual(utils.ovn_name(log_obj2['id']), acl.name[0])

        # Delete log_obj2 and ensure that logs are off and meter is no
        # longer used
        self.log_plugin.delete_log(self.ctxt, log_obj2['id'])
        self._check_sgrs(is_enabled=False)
        self.assertEqual([],
                         self.nb_api.meter_list().execute(check_error=True))

    def _add_logs_then_remove(self, event1, event2, sg_id=None, sgrs=None):
        # Events were previously not correctly applied on ACLs. This test
        # ensures that each event log only the necessary acls
        drop_true_events = (log_const.DROP_EVENT, log_const.ALL_EVENT)
        accept_true_events = (log_const.ALL_EVENT, log_const.ACCEPT_EVENT)
        # Check there are no acls with their logging active
        self._check_sgrs(sgrs=sgrs, is_enabled=False)
        if sg_id:
            self._check_sg_drop_acls(sg_id, is_enabled=False)
        else:
            self._check_acl_log_drop(is_enabled=False)

        # Add first log object
        log_data1 = self._log_data(sg_id=sg_id)
        log_data1['log']['event'] = event1
        log_obj1 = self.log_plugin.create_log(self.ctxt, log_data1)
        if sg_id:
            self._check_sg_drop_acls(sg_id,
                                     is_enabled=event1 in drop_true_events)
        else:
            self._check_acl_log_drop(is_enabled=event1 in drop_true_events)
        self._check_sgrs(sgrs=sgrs, is_enabled=event1 in accept_true_events)

        # Add second log object
        log_data2 = self._log_data(sg_id=sg_id)
        log_data2['log']['event'] = event2
        log_obj2 = self.log_plugin.create_log(self.ctxt, log_data2)
        drop_enabled = (event1 in drop_true_events or
                        event2 in drop_true_events)
        if sg_id:
            self._check_sg_drop_acls(sg_id, is_enabled=drop_enabled)
        else:
            self._check_acl_log_drop(is_enabled=drop_enabled)
        self._check_sgrs(sgrs=sgrs, is_enabled=(event1 in accept_true_events or
                                                event2 in accept_true_events))

        # Delete second log object
        self.log_plugin.delete_log(self.ctxt, log_obj2['id'])
        if sg_id:
            self._check_sg_drop_acls(sg_id,
                                     is_enabled=event1 in drop_true_events)
        else:
            self._check_acl_log_drop(is_enabled=event1 in drop_true_events)
        self._check_sgrs(sgrs=sgrs, is_enabled=event1 in accept_true_events)

        # Delete first log object
        self.log_plugin.delete_log(self.ctxt, log_obj1['id'])
        self._check_sgrs(sgrs=sgrs, is_enabled=False)
        if sg_id:
            self._check_sg_drop_acls(sg_id, is_enabled=False)
        else:
            self._check_acl_log_drop(is_enabled=False)

    def test_events_all_sg(self):
        self._add_logs_then_remove(log_const.DROP_EVENT, log_const.ALL_EVENT)
        self._add_logs_then_remove(
            log_const.ACCEPT_EVENT, log_const.DROP_EVENT)
        self._add_logs_then_remove(
            log_const.DROP_EVENT, log_const.ACCEPT_EVENT)

    def test_events_one_sg(self):
        self._add_logs_then_remove(log_const.DROP_EVENT, log_const.ALL_EVENT,
                                   sg_id=self.sg1, sgrs=self.sg1rs)
        self._add_logs_then_remove(
            log_const.ACCEPT_EVENT, log_const.DROP_EVENT, sg_id=self.sg2,
            sgrs=self.sg2rs)
        self._add_logs_then_remove(
            log_const.DROP_EVENT, log_const.ACCEPT_EVENT, sg_id=self.sg3,
            sgrs=self.sg3rs)

    def test_disable_logs(self):
        # This test ensures that acls are correctly disabled when having
        # multiple log objects.

        # Check there are no acls with their logging active
        sgrs = self.sg1rs
        self._check_sgrs(sgrs, is_enabled=False)
        self._check_sg_drop_acls(self.sg1, is_enabled=False)

        # Add accept log object
        log_data1 = self._log_data(sg_id=self.sg1)
        event1 = log_const.ACCEPT_EVENT
        log_data1['log']['event'] = event1
        log_obj1 = self.log_plugin.create_log(self.ctxt, log_data1)
        self._check_sg_drop_acls(self.sg1, is_enabled=False)
        self._check_sgrs(sgrs=sgrs, is_enabled=True)

        # Add drop log object
        log_data2 = self._log_data(sg_id=self.sg1)
        event2 = log_const.DROP_EVENT
        log_data2['log']['event'] = event2
        log_obj2 = self.log_plugin.create_log(self.ctxt, log_data2)
        self._check_sg_drop_acls(self.sg1, is_enabled=True)
        self._check_sgrs(sgrs=sgrs, is_enabled=True)

        # Disable drop log object and check it worked correctly
        log_data2['log']['enabled'] = False
        self.log_plugin.update_log(self.ctxt, log_obj2['id'], log_data2)
        self._check_sg_drop_acls(self.sg1, is_enabled=False)
        self._check_sgrs(sgrs=sgrs, is_enabled=True)

        # Enable drop log and create all log object
        log_data2['log']['enabled'] = True
        self.log_plugin.update_log(self.ctxt, log_obj2['id'], log_data2)
        self._check_sg_drop_acls(self.sg1, is_enabled=True)
        self._check_sgrs(sgrs=sgrs, is_enabled=True)

        log_data3 = self._log_data(sg_id=self.sg1)
        log_data3['log']['event'] = log_const.ALL_EVENT
        log_obj3 = self.log_plugin.create_log(self.ctxt, log_data3)
        self._check_sgrs(sgrs=sgrs, is_enabled=True)
        self._check_sg_drop_acls(self.sg1, is_enabled=True)

        # Disable all log object and check all acls are still enabled (because
        # of the other objects)
        log_data3['log']['enabled'] = False
        self.log_plugin.update_log(self.ctxt, log_obj3['id'], log_data3)
        self._check_sgrs(sgrs=sgrs, is_enabled=True)
        self._check_sg_drop_acls(self.sg1, is_enabled=True)

        # Disable accept log object and only drop traffic gets logged
        log_data1['log']['enabled'] = False
        self.log_plugin.update_log(self.ctxt, log_obj1['id'], log_data1)
        self._check_sgrs(sgrs=sgrs, is_enabled=False)
        self._check_sg_drop_acls(self.sg1, is_enabled=True)

    def test_add_rule_skips_already_configured_acls(self):
        """Adding a SG rule must not re-update ACLs that already have logging.

        When network logging is enabled and a new SG rule is created, only
        the newly created ACL should be updated. Existing ACLs that already
        have the correct logging configuration must be skipped. This is
        verified by checking that labels on pre-existing ACLs remain
        unchanged (labels are randomized on every _set_acls_log update).
        """
        log_obj = self.log_plugin.create_log(
            self.ctxt, self._log_data(sg_id=self.sg3))

        # Verify initial ACLs have logging enabled and record their labels.
        initial_labels = {}
        for sgr in self.sg3rs:
            acl = self._check_acl_log(sgr, is_enabled=True)
            self.assertEqual(utils.ovn_name(log_obj['id']), acl.name[0])
            initial_labels[sgr] = acl.label

        # Add a new rule to sg1; this triggers AFTER_CREATE → resource_update
        # → _set_acls_log on ALL ACLs of the port group.
        new_sgr = self._create_security_group_rule(self.sg3, 443)

        # The new ACL must have logging configured.
        new_acl = self._check_acl_log(new_sgr, is_enabled=True)
        self.assertEqual(utils.ovn_name(log_obj['id']), new_acl.name[0])

        # Pre-existing ACLs must NOT have been re-updated: their labels
        # must remain identical to the ones recorded before the new rule
        # was added.
        for sgr in self.sg3rs:
            acl = self._check_acl_log(sgr, is_enabled=True)
            self.assertEqual(initial_labels[sgr], acl.label,
                             'ACL for rule %s was unnecessarily re-updated'
                             % sgr)
        self._check_sg_drop_acls(self.sg3, is_enabled=True)


class LogApiTestCaseFlowSample(LogApiTestCaseComplex):
    """Flow-sample network logs on the ML2/OVN driver."""

    APP_NEW_ID = 11
    APP_EST_ID = 12
    COLLECTOR_ID = 13
    COLLECTOR_SET_ID = 1000
    PROBABILITY = 65535

    def setUp(self):
        super().setUp()
        if not self.nb_api.is_col_present('ACL', 'sample_new'):
            self.skipTest('The OVN Northbound schema has no ACL sampling')
        cfg.CONF.set_override('ovn_acl_sampling', True, group='network_log')
        cfg.CONF.set_override('ovn_acl_sampling_app_new_id', self.APP_NEW_ID,
                              group='network_log')
        cfg.CONF.set_override('ovn_acl_sampling_app_est_id', self.APP_EST_ID,
                              group='network_log')
        cfg.CONF.set_override('ovn_acl_sampling_collector_id',
                              self.COLLECTOR_ID, group='network_log')
        cfg.CONF.set_override('ovn_acl_sampling_collector_set_id',
                              self.COLLECTOR_SET_ID, group='network_log')
        cfg.CONF.set_override('ovn_acl_sampling_probability',
                              self.PROBABILITY, group='network_log')

    def _flow_log_data(self, sg_id, event=log_const.ALL_EVENT, enabled=True,
                       output_type=output_apidef.FLOW_SAMPLE):
        log_data = self._log_data(sg_id=sg_id, enabled=enabled)
        log_data['log']['event'] = event
        log_data['log']['output_type'] = output_type
        return log_data

    def _rows(self, table):
        return list(self.nb_api._tables[table].rows.values())

    def _owned_rows(self, table):
        return [row for row in self._rows(table)
                if ovn_sampling.is_owned_row(row)]

    def _sg_drop_acls(self, sg_id):
        pg = self.nb_api.get_port_group(utils.ovn_port_group_name(sg_id))
        return [acl for acl in pg.acls
                if acl.priority == ovn_const.ACL_PRIORITY_LOG_DROP and
                acl.action == ovn_const.ACL_ACTION_DROP]

    def _check_global_rows(self):
        apps = {app.type: app for app in self._owned_rows('Sampling_App')}
        self.assertEqual({ovn_const.OVN_SAMPLING_APP_ACL_NEW,
                          ovn_const.OVN_SAMPLING_APP_ACL_EST}, set(apps))
        self.assertEqual(self.APP_NEW_ID,
                         apps[ovn_const.OVN_SAMPLING_APP_ACL_NEW].id)
        self.assertEqual(self.APP_EST_ID,
                         apps[ovn_const.OVN_SAMPLING_APP_ACL_EST].id)
        collectors = self._owned_rows('Sample_Collector')
        self.assertEqual(1, len(collectors))
        collector = collectors[0]
        self.assertEqual(self.COLLECTOR_ID, collector.id)
        self.assertEqual(self.COLLECTOR_SET_ID, collector.set_id)
        self.assertEqual(self.PROBABILITY, collector.probability)
        self.assertEqual(ovn_const.OVN_SAMPLE_COLLECTOR_NAME, collector.name)
        return collector

    def _check_acl_sampled(self, acl, stages, collector=None):
        """Check which stages of an ACL reference a Neutron Sample."""
        collector = collector or self._owned_rows('Sample_Collector')[0]
        for stage in ovn_sampling.STAGES:
            ref = ovn_sampling.referenced_sample(acl, stage)
            key = ovn_sampling.STAGE_ACL_EXT_ID_KEY[stage]
            if stage in stages:
                self.assertIsNotNone(ref, '%s of ACL %s is not sampled' %
                                     (stage, acl.uuid))
                self.assertEqual([collector.uuid],
                                 ovn_sampling.sample_collector_uuids(ref))
                self.assertEqual(str(ref.metadata), acl.external_ids[key])
            else:
                self.assertIsNone(ref, '%s of ACL %s is sampled' %
                                  (stage, acl.uuid))
                self.assertNotIn(key, acl.external_ids)

    def _check_sgrs_sampled(self, sgrs, stages):
        for sgr in sgrs:
            acl = self._find_security_group_rule_row_by_id(sgr)
            self.assertIsNotNone(acl)
            self._check_acl_sampled(acl, stages)

    def _check_pg_sample_keys(self, sg_id, identities):
        """Check the Sample metadata the Port Group of a SG records.

        :param identities: the (observation action, stage) identities
            expected to be recorded; their values must be the metadata of
            existing Samples. The keys of other identities must be absent.
        """
        pg = self._find_security_group_row_by_id(sg_id)
        metadata = {str(ovn_sampling.sample_metadata(sample))
                    for sample in self._rows('Sample')}
        for identity, key in ovn_sampling.PG_SAMPLE_EXT_ID_KEY.items():
            if identity in identities:
                self.assertIn(pg.external_ids.get(key), metadata,
                              '%s is not recorded on %s' % (key, pg.name))
            else:
                self.assertNotIn(key, pg.external_ids)

    def test_create_and_delete(self):
        self.assertEqual([], self._rows('Sampling_App'))
        self.assertEqual([], self._rows('Sample_Collector'))

        log_obj = self.log_plugin.create_log(
            self.ctxt, self._flow_log_data(self.sg1))
        self.assertEqual(output_apidef.FLOW_SAMPLE, log_obj['output_type'])
        collector = self._check_global_rows()
        # Stateful allow rules are sampled on both connection stages.
        self._check_sgrs_sampled(self.sg1rs, ovn_sampling.STAGES)
        self._check_sgrs_sampled(self.sg2rs + self.sg3rs, ())
        # The drop ACLs of the security group exist without packet logging
        # and are sampled on the new stage.
        drop_acls = self._sg_drop_acls(self.sg1)
        self.assertEqual(2, len(drop_acls))
        for acl in drop_acls:
            self.assertFalse(acl.log)
            self._check_acl_sampled(acl, (ovn_sampling.STAGE_NEW,),
                                    collector)
        self.assertEqual([], self._sg_drop_acls(self.sg2))
        # One Sample per stage and observation action.
        samples = {ovn_sampling.referenced_sample(acl, stage).uuid
                   for acl in self._sg_drop_acls(self.sg1) + [
                       self._find_security_group_rule_row_by_id(sgr)
                       for sgr in self.sg1rs]
                   for stage in ovn_sampling.STAGES
                   if ovn_sampling.referenced_sample(acl, stage)}
        self.assertEqual(3, len(samples))
        # The Port Group records the metadata of the three identities.
        self._check_pg_sample_keys(
            self.sg1, set(ovn_sampling.PG_SAMPLE_EXT_ID_KEY))
        self._check_pg_sample_keys(self.sg2, set())

        self.log_plugin.delete_log(self.ctxt, log_obj['id'])
        self._check_sgrs_sampled(self.sgrs, ())
        self.assertEqual([], self._sg_drop_acls(self.sg1))
        self._check_pg_sample_keys(self.sg1, set())
        # The global rows are kept for the next log.
        self._check_global_rows()

    def test_disable_and_enable(self):
        log_data = self._flow_log_data(self.sg2, event=log_const.ACCEPT_EVENT)
        log_obj = self.log_plugin.create_log(self.ctxt, log_data)
        self._check_sgrs_sampled(self.sg2rs, ovn_sampling.STAGES)
        self.assertEqual([], self._sg_drop_acls(self.sg2))
        allow_identities = {(ovn_sampling.OBSERVE_ALLOW, stage)
                            for stage in ovn_sampling.STAGES}
        self._check_pg_sample_keys(self.sg2, allow_identities)

        log_data['log']['enabled'] = False
        self.log_plugin.update_log(self.ctxt, log_obj['id'], log_data)
        self._check_sgrs_sampled(self.sg2rs, ())
        self._check_pg_sample_keys(self.sg2, set())

        log_data['log']['enabled'] = True
        self.log_plugin.update_log(self.ctxt, log_obj['id'], log_data)
        self._check_sgrs_sampled(self.sg2rs, ovn_sampling.STAGES)
        self._check_pg_sample_keys(self.sg2, allow_identities)

    def test_new_rule_is_sampled(self):
        self.log_plugin.create_log(self.ctxt, self._flow_log_data(self.sg1))
        new_rule = self._create_security_group_rule(self.sg1, 443)
        self._check_sgrs_sampled(self.sg1rs + [new_rule],
                                 ovn_sampling.STAGES)

    def test_drop_acls_shared_with_packet_log(self):
        packet_data = self._log_data(sg_id=self.sg3)
        packet_data['log']['event'] = log_const.DROP_EVENT
        packet_log = self.log_plugin.create_log(self.ctxt, packet_data)
        flow_log = self.log_plugin.create_log(
            self.ctxt, self._flow_log_data(self.sg3,
                                           event=log_const.DROP_EVENT))
        drop_acls = self._sg_drop_acls(self.sg3)
        self.assertEqual(2, len(drop_acls))
        for acl in drop_acls:
            self.assertTrue(acl.log)
            self._check_acl_sampled(acl, (ovn_sampling.STAGE_NEW,))
            # The label of a logged and sampled ACL is its Sample metadata.
            self.assertEqual(
                ovn_sampling.referenced_sample(
                    acl, ovn_sampling.STAGE_NEW).metadata, acl.label)
        self._check_sgrs_sampled(self.sg3rs, ())

        self.log_plugin.delete_log(self.ctxt, packet_log['id'])
        drop_acls = self._sg_drop_acls(self.sg3)
        self.assertEqual(2, len(drop_acls))
        for acl in drop_acls:
            self.assertFalse(acl.log)
            self._check_acl_sampled(acl, (ovn_sampling.STAGE_NEW,))

        self.log_plugin.delete_log(self.ctxt, flow_log['id'])
        self.assertEqual([], self._sg_drop_acls(self.sg3))

    def test_foreign_reference_is_rejected(self):
        acl = self._find_security_group_rule_row_by_id(self.sg2rs[0])
        # A Sample row is garbage collected unless an ACL references it in
        # the transaction that creates it.
        with self.nb_api.transaction(check_error=True) as txn:
            collector = txn.add(self.nb_api.db_create(
                'Sample_Collector', id=200, name='foreign', probability=1,
                set_id=7))
            sample = txn.add(self.nb_api.db_create(
                'Sample', metadata=4242, collectors=[collector]))
            txn.add(self.nb_api.db_set('ACL', acl.uuid,
                                       ('sample_new', [sample])))
        foreign_sample = sample.result

        self.assertRaises(n_exc.DriverCallError, self.log_plugin.create_log,
                          self.ctxt, self._flow_log_data(self.sg2))
        acl = self._find_security_group_rule_row_by_id(self.sg2rs[0])
        self.assertEqual([foreign_sample], [s.uuid for s in acl.sample_new])

    def test_sampling_disabled_is_rejected(self):
        cfg.CONF.set_override('ovn_acl_sampling', False, group='network_log')
        self.assertRaises(log_exc.LogOutputTypeNotSupported,
                          self.log_plugin.create_log, self.ctxt,
                          self._flow_log_data(self.sg1))
        self.assertEqual([], self._rows('Sampling_App'))

    def test_selector_is_validated(self):
        self.assertRaises(log_exc.FlowSampleSelectorNotSupported,
                          self.log_plugin.create_log, self.ctxt,
                          self._flow_log_data(None))
        log_data = self._flow_log_data(self.sg1)
        log_data['log']['target_id'] = self.port1
        self.assertRaises(log_exc.FlowSampleSelectorNotSupported,
                          self.log_plugin.create_log, self.ctxt, log_data)

    def test_statefulness_change_reapplies_sampling(self):
        sg = self._create_security_group('test_sg_stateful')
        rule = self._create_security_group_rule(sg, 8080)
        self.log_plugin.create_log(self.ctxt, self._flow_log_data(sg))
        self._check_sgrs_sampled([rule], ovn_sampling.STAGES)

        data = {'security_group': {'stateful': False}}
        req = self.new_update_request('security-groups', data, sg, self.fmt)
        res = req.get_response(self.api)
        self.assertEqual(200, res.status_int)
        # Stateless rules are only sampled on the new stage.
        self._check_sgrs_sampled([rule], (ovn_sampling.STAGE_NEW,))

    def test_reconcile_sampling_repairs_references(self):
        self.log_plugin.create_log(self.ctxt, self._flow_log_data(self.sg1))
        acl = self._find_security_group_rule_row_by_id(self.sg1rs[0])
        self.nb_api.db_set('ACL', acl.uuid, ('sample_new', [])).execute(
            check_error=True)
        self._check_acl_sampled(
            self._find_security_group_rule_row_by_id(self.sg1rs[0]),
            (ovn_sampling.STAGE_EST,))

        self.assertEqual([self.sg1],
                         self.log_driver.reconcile_sampling(self.ctxt))
        self._check_sgrs_sampled(self.sg1rs, ovn_sampling.STAGES)

    def test_loggable_resources_advertise_output_types(self):
        resources = self.log_plugin.get_loggable_resources(self.ctxt)
        self.assertIn({'type': log_const.SECURITY_GROUP,
                       'output_types': [output_apidef.FLOW_SAMPLE,
                                        output_apidef.PACKET_LOG]},
                      resources)
        cfg.CONF.set_override('ovn_acl_sampling', False, group='network_log')
        resources = self.log_plugin.get_loggable_resources(self.ctxt)
        self.assertIn({'type': log_const.SECURITY_GROUP,
                       'output_types': [output_apidef.PACKET_LOG]},
                      resources)
