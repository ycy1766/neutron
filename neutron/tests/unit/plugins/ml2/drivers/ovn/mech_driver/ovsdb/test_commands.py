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

from unittest import mock
import uuid

from neutron_lib import constants as n_const
from oslo_utils import uuidutils
from ovsdbapp.backend.ovs_idl import idlutils

from neutron.common.ovn import constants as ovn_const
from neutron.common.ovn import exceptions as ovn_exc
from neutron.common.ovn import sampling
from neutron.plugins.ml2.drivers.ovn.mech_driver.ovsdb import commands
from neutron.tests import base
from neutron.tests.unit import fake_resources as fakes


class TestBaseCommandHelpers(base.BaseTestCase):
    def setUp(self):
        super().setUp()
        self.column = 'ovn'
        self.new_value = '1'
        self.old_value = '2'

    def _get_fake_row_mutate(self):
        return fakes.FakeOvsdbRow.create_one_ovsdb_row(
            attrs={self.column: []})

    def test__addvalue_to_list(self):
        fake_row_mutate = self._get_fake_row_mutate()
        commands._addvalue_to_list(
            fake_row_mutate, self.column, self.new_value)
        fake_row_mutate.addvalue.assert_called_once_with(
            self.column, self.new_value)
        fake_row_mutate.verify.assert_not_called()

    def test__delvalue_from_list(self):
        fake_row_mutate = self._get_fake_row_mutate()
        commands._delvalue_from_list(
            fake_row_mutate, self.column, self.old_value)
        fake_row_mutate.delvalue.assert_called_once_with(
            self.column, self.old_value)
        fake_row_mutate.verify.assert_not_called()

    def test__updatevalues_in_list_none(self):
        fake_row_mutate = self._get_fake_row_mutate()
        commands._updatevalues_in_list(fake_row_mutate, self.column)
        fake_row_mutate.addvalue.assert_not_called()
        fake_row_mutate.delvalue.assert_not_called()
        fake_row_mutate.verify.assert_not_called()

    def test__updatevalues_in_list_empty(self):
        fake_row_mutate = self._get_fake_row_mutate()
        commands._updatevalues_in_list(fake_row_mutate, self.column, [], [])
        fake_row_mutate.addvalue.assert_not_called()
        fake_row_mutate.delvalue.assert_not_called()
        fake_row_mutate.verify.assert_not_called()

    def test__updatevalues_in_list(self):
        fake_row_mutate = self._get_fake_row_mutate()
        commands._updatevalues_in_list(
            fake_row_mutate, self.column,
            new_values=[self.new_value],
            old_values=[self.old_value])
        fake_row_mutate.addvalue.assert_called_once_with(
            self.column, self.new_value)
        fake_row_mutate.delvalue.assert_called_once_with(
            self.column, self.old_value)
        fake_row_mutate.verify.assert_not_called()


class TestBaseCommand(base.BaseTestCase):
    def setUp(self):
        super().setUp()
        self.ovn_api = fakes.FakeOvsdbNbOvnIdl()
        self.transaction = fakes.FakeOvsdbTransaction()
        self.ovn_api.transaction = self.transaction


class TestCheckLivenessCommand(TestBaseCommand):
    def test_check_liveness(self):
        old_ng_cfg = self.ovn_api.nb_global.ng_cfg
        cmd = commands.CheckLivenessCommand(self.ovn_api)
        cmd.run_idl(self.transaction)
        self.assertNotEqual(cmd.result, old_ng_cfg)


class TestAddLSwitchPortCommand(TestBaseCommand):

    def test_lswitch_not_found(self):
        with mock.patch.object(idlutils, 'row_by_value',
                               side_effect=idlutils.RowNotFound):
            cmd = commands.AddLSwitchPortCommand(
                self.ovn_api, 'fake-lsp', 'fake-lswitch', may_exist=True)
            self.assertRaises(RuntimeError, cmd.run_idl, self.transaction)
            self.transaction.insert.assert_not_called()

    def test_lswitch_port_exists(self):
        with mock.patch.object(idlutils, 'row_by_value',
                               return_value=mock.Mock()):
            cmd = commands.AddLSwitchPortCommand(
                self.ovn_api, 'fake-lsp', 'fake-lswitch', may_exist=True)
            cmd.run_idl(self.transaction)
            self.transaction.insert.assert_not_called()

    def test_lswitch_port_add_exists(self):
        fake_lswitch = fakes.FakeOvsdbRow.create_one_ovsdb_row()
        with mock.patch.object(idlutils, 'row_by_value',
                               return_value=fake_lswitch):
            fake_lsp = fakes.FakeOvsdbRow.create_one_ovsdb_row()
            self.ovn_api._tables['Logical_Switch_Port'].rows[fake_lsp.uuid] = \
                fake_lsp
            self.transaction.insert.return_value = fake_lsp
            cmd = commands.AddLSwitchPortCommand(
                self.ovn_api, fake_lsp.name, fake_lswitch.name,
                may_exist=False)
            cmd.run_idl(self.transaction)
            # NOTE(rtheis): Mocking the transaction allows this insert
            # to succeed when it normally would fail due the duplicate name.
            self.transaction.insert.assert_called_once_with(
                self.ovn_api._tables['Logical_Switch_Port'])

    def _test_lswitch_port_add(self, may_exist=True):
        lsp_name = 'fake-lsp'
        fake_lswitch = fakes.FakeOvsdbRow.create_one_ovsdb_row()
        with mock.patch.object(idlutils, 'row_by_value',
                               side_effect=[fake_lswitch, None]):
            fake_lsp = fakes.FakeOvsdbRow.create_one_ovsdb_row(
                attrs={'foo': None})
            self.transaction.insert.return_value = fake_lsp
            cmd = commands.AddLSwitchPortCommand(
                self.ovn_api, lsp_name, fake_lswitch.name,
                may_exist=may_exist, foo='bar')
            cmd.run_idl(self.transaction)
            self.transaction.insert.assert_called_once_with(
                self.ovn_api._tables['Logical_Switch_Port'])
            fake_lswitch.addvalue.assert_called_once_with(
                'ports', fake_lsp.uuid)
            self.assertEqual(lsp_name, fake_lsp.name)
            self.assertEqual('bar', fake_lsp.foo)

    def test_lswitch_port_add_may_exist(self):
        self._test_lswitch_port_add(may_exist=True)

    def test_lswitch_port_add_ignore_exists(self):
        self._test_lswitch_port_add(may_exist=False)

    def _test_lswitch_port_add_with_dhcp(self, dhcpv4_opts, dhcpv6_opts):
        lsp_name = 'fake-lsp'
        fake_lswitch = fakes.FakeOvsdbRow.create_one_ovsdb_row()
        fake_lsp = fakes.FakeOvsdbRow.create_one_ovsdb_row()
        self.transaction.insert.return_value = fake_lsp
        with mock.patch.object(idlutils, 'row_by_value',
                               side_effect=[fake_lswitch, None]):
            cmd = commands.AddLSwitchPortCommand(
                self.ovn_api, lsp_name, fake_lswitch.name,
                may_exist=True, dhcpv4_options=dhcpv4_opts,
                dhcpv6_options=dhcpv6_opts)
            if not isinstance(dhcpv4_opts, list):
                dhcpv4_opts.result = 'fake-uuid-1'
            if not isinstance(dhcpv6_opts, list):
                dhcpv6_opts.result = 'fake-uuid-2'
            self.transaction.insert.reset_mock()
            cmd.run_idl(self.transaction)
            self.transaction.insert.assert_called_once_with(
                self.ovn_api.lsp_table)
            fake_lswitch.addvalue.assert_called_once_with(
                'ports', fake_lsp.uuid)
            self.assertEqual(lsp_name, fake_lsp.name)
            if isinstance(dhcpv4_opts, list):
                self.assertEqual(dhcpv4_opts, fake_lsp.dhcpv4_options)
            else:
                self.assertEqual(['fake-uuid-1'], fake_lsp.dhcpv4_options)
            if isinstance(dhcpv6_opts, list):
                self.assertEqual(dhcpv6_opts, fake_lsp.dhcpv6_options)
            else:
                self.assertEqual(['fake-uuid-2'], fake_lsp.dhcpv6_options)

    def test_lswitch_port_add_with_dhcp(self):
        dhcpv4_opts_cmd = commands.AddDHCPOptionsCommand(
            self.ovn_api, mock.ANY, port_id=mock.ANY)
        dhcpv6_opts_cmd = commands.AddDHCPOptionsCommand(
            self.ovn_api, mock.ANY, port_id=mock.ANY)
        for dhcpv4_opts in ([], ['fake-uuid-1'], dhcpv4_opts_cmd):
            for dhcpv6_opts in ([], ['fake-uuid-2'], dhcpv6_opts_cmd):
                self._test_lswitch_port_add_with_dhcp(dhcpv4_opts, dhcpv6_opts)


class TestSetLSwitchPortCommand(TestBaseCommand):

    def _test_lswitch_port_update_no_exist(self, if_exists=True):
        with mock.patch.object(idlutils, 'row_by_value',
                               side_effect=idlutils.RowNotFound):
            cmd = commands.SetLSwitchPortCommand(
                self.ovn_api, 'fake-lsp', external_ids_update=None,
                if_exists=if_exists)
            if if_exists:
                cmd.run_idl(self.transaction)
            else:
                self.assertRaises(RuntimeError, cmd.run_idl, self.transaction)

    def test_lswitch_port_no_exist_ignore(self):
        self._test_lswitch_port_update_no_exist(if_exists=True)

    def test_lswitch_port_no_exist_fail(self):
        self._test_lswitch_port_update_no_exist(if_exists=False)

    def test_lswitch_port_update(self):
        ext_ids = {ovn_const.OVN_PORT_NAME_EXT_ID_KEY: 'test'}
        new_ext_ids = {ovn_const.OVN_PORT_NAME_EXT_ID_KEY: 'test-new'}
        fake_lsp = fakes.FakeOvsdbRow.create_one_ovsdb_row(
            attrs={'external_ids': ext_ids})
        with mock.patch.object(idlutils, 'row_by_value',
                               return_value=fake_lsp):
            cmd = commands.SetLSwitchPortCommand(
                self.ovn_api, fake_lsp.name, external_ids_update=new_ext_ids,
                if_exists=True, external_ids=new_ext_ids)
            cmd.run_idl(self.transaction)
            self.assertEqual(new_ext_ids, fake_lsp.external_ids)

    def _test_lswitch_port_update_del_dhcp(self, clear_v4_opts,
                                           clear_v6_opts, set_v4_opts=False,
                                           set_v6_opts=False):
        ext_ids = {ovn_const.OVN_PORT_NAME_EXT_ID_KEY: 'test'}
        dhcp_options_tbl = self.ovn_api._tables['DHCP_Options']
        fake_dhcpv4_opts = fakes.FakeOvsdbRow.create_one_ovsdb_row(
            attrs={'external_ids': {'port_id': 'fake-lsp'}})
        dhcp_options_tbl.rows[fake_dhcpv4_opts.uuid] = fake_dhcpv4_opts
        fake_dhcpv6_opts = fakes.FakeOvsdbRow.create_one_ovsdb_row(
            attrs={'external_ids': {'port_id': 'fake-lsp'}})
        dhcp_options_tbl.rows[fake_dhcpv6_opts.uuid] = fake_dhcpv6_opts
        fake_lsp = fakes.FakeOvsdbRow.create_one_ovsdb_row(
            attrs={'name': 'fake-lsp',
                   'external_ids': ext_ids,
                   'dhcpv4_options': [fake_dhcpv4_opts],
                   'dhcpv6_options': [fake_dhcpv6_opts]})

        columns = {}
        if clear_v4_opts:
            columns['dhcpv4_options'] = []
        elif set_v4_opts:
            columns['dhcpv4_options'] = [fake_dhcpv4_opts.uuid]
        if clear_v6_opts:
            columns['dhcpv6_options'] = []
        elif set_v6_opts:
            columns['dhcpv6_options'] = [fake_dhcpv6_opts.uuid]

        with mock.patch.object(idlutils, 'row_by_value',
                               return_value=fake_lsp):
            cmd = commands.SetLSwitchPortCommand(
                self.ovn_api, fake_lsp.name, external_ids_update=None,
                if_exists=True, **columns)
            cmd.run_idl(self.transaction)

            if clear_v4_opts and clear_v6_opts:
                fake_dhcpv4_opts.delete.assert_called_once_with()
                fake_dhcpv6_opts.delete.assert_called_once_with()
            elif clear_v4_opts:
                # not clear_v6_opts and set_v6_opts is any
                fake_dhcpv4_opts.delete.assert_called_once_with()
                fake_dhcpv6_opts.delete.assert_not_called()
            elif clear_v6_opts:
                # not clear_v4_opts and set_v6_opts is any
                fake_dhcpv4_opts.delete.assert_not_called()
                fake_dhcpv6_opts.delete.assert_called_once_with()
            else:
                # not clear_v4_opts and not clear_v6_opts and
                # set_v4_opts is any and set_v6_opts is any
                fake_dhcpv4_opts.delete.assert_not_called()
                fake_dhcpv6_opts.delete.assert_not_called()

    def test_lswitch_port_update_del_port_dhcpv4_options(self):
        self._test_lswitch_port_update_del_dhcp(True, False)

    def test_lswitch_port_update_del_port_dhcpv6_options(self):
        self._test_lswitch_port_update_del_dhcp(False, True)

    def test_lswitch_port_update_del_all_port_dhcp_options(self):
        self._test_lswitch_port_update_del_dhcp(True, True)

    def test_lswitch_port_update_del_no_port_dhcp_options(self):
        self._test_lswitch_port_update_del_dhcp(False, False)

    def test_lswitch_port_update_set_port_dhcpv4_options(self):
        self._test_lswitch_port_update_del_dhcp(False, True, set_v4_opts=True)

    def test_lswitch_port_update_set_port_dhcpv6_options(self):
        self._test_lswitch_port_update_del_dhcp(True, False, set_v6_opts=True)

    def test_lswitch_port_update_set_all_port_dhcp_options(self):
        self._test_lswitch_port_update_del_dhcp(False, False, set_v4_opts=True,
                                                set_v6_opts=True)

    def _test_lswitch_port_update_with_dhcp(self, dhcpv4_opts, dhcpv6_opts):
        ext_ids = {ovn_const.OVN_PORT_NAME_EXT_ID_KEY: 'test'}
        fake_lsp = fakes.FakeOvsdbRow.create_one_ovsdb_row(
            attrs={'name': 'fake-lsp',
                   'external_ids': ext_ids,
                   'dhcpv4_options': ['fake-v4-subnet-dhcp-opt'],
                   'dhcpv6_options': ['fake-v6-subnet-dhcp-opt']})
        with mock.patch.object(idlutils, 'row_by_value',
                               return_value=fake_lsp):
            cmd = commands.SetLSwitchPortCommand(
                self.ovn_api, fake_lsp.name, external_ids_update=ext_ids,
                if_exists=True,
                external_ids=ext_ids, dhcpv4_options=dhcpv4_opts,
                dhcpv6_options=dhcpv6_opts)
            if not isinstance(dhcpv4_opts, list):
                dhcpv4_opts.result = 'fake-uuid-1'
            if not isinstance(dhcpv6_opts, list):
                dhcpv6_opts.result = 'fake-uuid-2'
            cmd.run_idl(self.transaction)
            if isinstance(dhcpv4_opts, list):
                self.assertEqual(dhcpv4_opts, fake_lsp.dhcpv4_options)
            else:
                self.assertEqual(['fake-uuid-1'], fake_lsp.dhcpv4_options)
            if isinstance(dhcpv6_opts, list):
                self.assertEqual(dhcpv6_opts, fake_lsp.dhcpv6_options)
            else:
                self.assertEqual(['fake-uuid-2'], fake_lsp.dhcpv6_options)

    def test_lswitch_port_update_with_dhcp(self):
        v4_dhcp_cmd = commands.AddDHCPOptionsCommand(self.ovn_api, mock.ANY,
                                                     port_id=mock.ANY)
        v6_dhcp_cmd = commands.AddDHCPOptionsCommand(self.ovn_api, mock.ANY,
                                                     port_id=mock.ANY)
        for dhcpv4_opts in ([], ['fake-v4-subnet-dhcp-opt'], v4_dhcp_cmd):
            for dhcpv6_opts in ([], ['fake-v6-subnet-dhcp-opt'], v6_dhcp_cmd):
                self._test_lswitch_port_update_with_dhcp(
                    dhcpv4_opts, dhcpv6_opts)


class TestDelLSwitchPortCommand(TestBaseCommand):

    def _test_lswitch_no_exist(self, if_exists=True):
        with mock.patch.object(idlutils, 'row_by_value',
                               side_effect=['fake-lsp', idlutils.RowNotFound]):
            cmd = commands.DelLSwitchPortCommand(
                self.ovn_api, 'fake-lsp', 'fake-lswitch', if_exists=if_exists)
            if if_exists:
                cmd.run_idl(self.transaction)
            else:
                self.assertRaises(RuntimeError, cmd.run_idl, self.transaction)

    def test_lswitch_no_exist_ignore(self):
        self._test_lswitch_no_exist(if_exists=True)

    def test_lswitch_no_exist_fail(self):
        self._test_lswitch_no_exist(if_exists=False)

    def _test_lswitch_port_del_no_exist(self, if_exists=True):
        with mock.patch.object(idlutils, 'row_by_value',
                               side_effect=idlutils.RowNotFound):
            cmd = commands.DelLSwitchPortCommand(
                self.ovn_api, 'fake-lsp', 'fake-lswitch', if_exists=if_exists)
            if if_exists:
                cmd.run_idl(self.transaction)
            else:
                self.assertRaises(RuntimeError, cmd.run_idl, self.transaction)

    def test_lswitch_port_no_exist_ignore(self):
        self._test_lswitch_port_del_no_exist(if_exists=True)

    def test_lswitch_port_no_exist_fail(self):
        self._test_lswitch_port_del_no_exist(if_exists=False)

    def test_lswitch_port_del(self):
        fake_lsp = mock.MagicMock()
        fake_lswitch = fakes.FakeOvsdbRow.create_one_ovsdb_row(
            attrs={'ports': [fake_lsp]})
        self.ovn_api._tables['Logical_Switch_Port'].rows[fake_lsp.uuid] = \
            fake_lsp
        with mock.patch.object(idlutils, 'row_by_value',
                               side_effect=[fake_lsp, fake_lswitch]):
            cmd = commands.DelLSwitchPortCommand(
                self.ovn_api, fake_lsp.name, fake_lswitch.name, if_exists=True)
            cmd.run_idl(self.transaction)
            fake_lswitch.delvalue.assert_called_once_with('ports', fake_lsp)
            fake_lsp.delete.assert_called_once_with()

    def _test_lswitch_port_del_delete_dhcp_opt(self, dhcpv4_opt_ext_ids,
                                               dhcpv6_opt_ext_ids):
        ext_ids = {ovn_const.OVN_PORT_NAME_EXT_ID_KEY: 'test'}
        fake_dhcpv4_options = fakes.FakeOvsdbRow.create_one_ovsdb_row(
            attrs={'external_ids': dhcpv4_opt_ext_ids})
        self.ovn_api._tables['DHCP_Options'].rows[fake_dhcpv4_options.uuid] = \
            fake_dhcpv4_options
        fake_dhcpv6_options = fakes.FakeOvsdbRow.create_one_ovsdb_row(
            attrs={'external_ids': dhcpv6_opt_ext_ids})
        self.ovn_api._tables['DHCP_Options'].rows[fake_dhcpv6_options.uuid] = \
            fake_dhcpv6_options
        fake_lsp = fakes.FakeOvsdbRow.create_one_ovsdb_row(
            attrs={'name': 'lsp',
                   'external_ids': ext_ids,
                   'dhcpv4_options': [fake_dhcpv4_options],
                   'dhcpv6_options': [fake_dhcpv6_options],
                   'type': '',
                   },
        )
        self.ovn_api._tables['Logical_Switch_Port'].rows[fake_lsp.uuid] = \
            fake_lsp
        fake_lswitch = fakes.FakeOvsdbRow.create_one_ovsdb_row(
            attrs={'ports': [fake_lsp]})
        with mock.patch.object(idlutils, 'row_by_value',
                               side_effect=[fake_lsp, fake_lswitch]):
            cmd = commands.DelLSwitchPortCommand(
                self.ovn_api, fake_lsp.name, fake_lswitch.name, if_exists=True)
            cmd.run_idl(self.transaction)
            fake_lswitch.delvalue.assert_called_once_with('ports', fake_lsp)
            fake_lsp.delete.assert_called_once_with()
            if 'port_id' in dhcpv4_opt_ext_ids:
                fake_dhcpv4_options.delete.assert_called_once_with()
            else:
                fake_dhcpv4_options.delete.assert_not_called()
            if 'port_id' in dhcpv6_opt_ext_ids:
                fake_dhcpv6_options.delete.assert_called_once_with()
            else:
                fake_dhcpv6_options.delete.assert_not_called()

    def test_lswitch_port_del_delete_dhcp_opt(self):
        for v4_ext_ids in ({'subnet_id': 'fake-ls0'},
                           {'subnet_id': 'fake-ls0', 'port_id': 'lsp'}):
            for v6_ext_ids in ({'subnet_id': 'fake-ls1'},
                               {'subnet_id': 'fake-ls1', 'port_id': 'lsp'}):
                self._test_lswitch_port_del_delete_dhcp_opt(
                    v4_ext_ids, v6_ext_ids)


class TestUpdateLRouterCommand(TestBaseCommand):

    def _test_lrouter_update_no_exist(self, if_exists=True):
        with mock.patch.object(idlutils, 'row_by_value') as fake_row_by_value:
            cmd = commands.UpdateLRouterCommand(
                self.ovn_api, 'fake-lrouter', if_exists=if_exists)
            if if_exists:
                fake_row_by_value.return_value = None
                cmd.run_idl(self.transaction)
            else:
                fake_row_by_value.side_effect = idlutils.RowNotFound
                self.assertRaises(RuntimeError, cmd.run_idl, self.transaction)

    def test_lrouter_no_exist_ignore(self):
        self._test_lrouter_update_no_exist(if_exists=True)

    def test_lrouter_no_exist_fail(self):
        self._test_lrouter_update_no_exist(if_exists=False)

    def test_lrouter_update(self):
        ext_ids = {ovn_const.OVN_ROUTER_NAME_EXT_ID_KEY: 'richard'}
        new_ext_ids = {ovn_const.OVN_ROUTER_NAME_EXT_ID_KEY: 'richard-new'}
        fake_lrouter = fakes.FakeOvsdbRow.create_one_ovsdb_row(
            attrs={'external_ids': ext_ids})
        with mock.patch.object(idlutils, 'row_by_value',
                               return_value=fake_lrouter):
            cmd = commands.UpdateLRouterCommand(
                self.ovn_api, fake_lrouter.name, if_exists=True,
                external_ids=new_ext_ids)
            cmd.run_idl(self.transaction)
            self.assertEqual(new_ext_ids, fake_lrouter.external_ids)


class TestLrDelCommand(TestBaseCommand):

    def _test_lrouter_del_no_exist(self, if_exists=True):
        with mock.patch.object(self.ovn_api, 'lookup',
                               side_effect=[None, idlutils.RowNotFound]):
            cmd = commands.LrDelCommand(
                self.ovn_api, 'fake-lrouter', if_exists=if_exists)
            if if_exists:
                cmd.run_idl(self.transaction)
            else:
                self.assertRaises(RuntimeError, cmd.run_idl, self.transaction)

    def test_lrouter_no_exist_ignore(self):
        self._test_lrouter_del_no_exist(if_exists=True)

    def test_lrouter_no_exist_fail(self):
        self._test_lrouter_del_no_exist(if_exists=False)

    def test_lrouter_del(self):
        fake_lrp1 = fakes.FakeOvsdbRow.create_one_ovsdb_row()
        fake_lrp2 = fakes.FakeOvsdbRow.create_one_ovsdb_row()
        fake_lrouter = fakes.FakeOvsdbRow.create_one_ovsdb_row()
        fake_lrouter.ports = [fake_lrp1, fake_lrp2]
        fake_hcg = fakes.FakeOvsdbRow.create_one_ovsdb_row()
        self.ovn_api._tables['Logical_Router'].rows[fake_lrouter.uuid] = \
            fake_lrouter
        with mock.patch.object(self.ovn_api, 'lookup',
                               side_effect=[fake_hcg, fake_lrouter,
                                            fake_lrouter]):
            cmd = commands.LrDelCommand(
                self.ovn_api, fake_lrouter.name, if_exists=True)
            cmd.run_idl(self.transaction)
            fake_lrp1.delvalue.assert_called_once_with(
                'ha_chassis_group', fake_hcg)
            fake_lrp2.delvalue.assert_called_once_with(
                'ha_chassis_group', fake_hcg)
            fake_hcg.delete.assert_called_once_with()
            fake_lrouter.delete.assert_called_once_with()


class TestAddLRouterPortCommand(TestBaseCommand):

    def test_lrouter_not_found(self):
        with mock.patch.object(idlutils, 'row_by_value',
                               side_effect=idlutils.RowNotFound):
            cmd = commands.AddLRouterPortCommand(
                self.ovn_api, 'fake-lrp', 'fake-lrouter', may_exist=False)
            self.assertRaises(RuntimeError, cmd.run_idl, self.transaction)
            self.transaction.insert.assert_not_called()

    def test_lrouter_port_exists(self):
        with mock.patch.object(idlutils, 'row_by_value',
                               return_value=mock.ANY):
            cmd = commands.AddLRouterPortCommand(
                self.ovn_api, 'fake-lrp', 'fake-lrouter', may_exist=False)
            self.assertRaises(RuntimeError, cmd.run_idl, self.transaction)
            self.transaction.insert.assert_not_called()

    def test_lrouter_port_may_exist(self):
        with mock.patch.object(idlutils, 'row_by_value',
                               return_value=mock.ANY):
            cmd = commands.AddLRouterPortCommand(
                self.ovn_api, 'fake-lrp', 'fake-lrouter', may_exist=True)
            cmd.run_idl(self.transaction)
            self.transaction.insert.assert_not_called()

    def test_lrouter_port_add(self):
        fake_lrouter = fakes.FakeOvsdbRow.create_one_ovsdb_row()
        with mock.patch.object(idlutils, 'row_by_value',
                               side_effect=[fake_lrouter,
                                            idlutils.RowNotFound]):
            fake_lrp = fakes.FakeOvsdbRow.create_one_ovsdb_row(
                attrs={'foo': None})
            self.transaction.insert.return_value = fake_lrp
            cmd = commands.AddLRouterPortCommand(
                self.ovn_api, 'fake-lrp', fake_lrouter.name, may_exist=False,
                foo='bar')
            cmd.run_idl(self.transaction)
            self.transaction.insert.assert_called_once_with(
                self.ovn_api._tables['Logical_Router_Port'])
            self.assertEqual('fake-lrp', fake_lrp.name)
            fake_lrouter.addvalue.assert_called_once_with('ports', fake_lrp)
            self.assertEqual('bar', fake_lrp.foo)


class TestUpdateLRouterPortCommand(TestBaseCommand):

    def _test_lrouter_port_update_no_exist(self, if_exists=True):
        with mock.patch.object(idlutils, 'row_by_value',
                               side_effect=idlutils.RowNotFound):
            cmd = commands.UpdateLRouterPortCommand(
                self.ovn_api, 'fake-lrp', if_exists=if_exists)
            if if_exists:
                cmd.run_idl(self.transaction)
            else:
                self.assertRaises(RuntimeError, cmd.run_idl, self.transaction)

    def test_lrouter_port_no_exist_ignore(self):
        self._test_lrouter_port_update_no_exist(if_exists=True)

    def test_lrouter_port_no_exist_fail(self):
        self._test_lrouter_port_update_no_exist(if_exists=False)

    def test_lrouter_port_update(self):
        old_networks = []
        new_networks = ['10.1.0.0/24']
        fake_lrp = fakes.FakeOvsdbRow.create_one_ovsdb_row(
            attrs={'networks': old_networks})
        with mock.patch.object(idlutils, 'row_by_value',
                               return_value=fake_lrp):
            cmd = commands.UpdateLRouterPortCommand(
                self.ovn_api, fake_lrp.name, if_exists=True,
                networks=new_networks)
            cmd.run_idl(self.transaction)
            self.assertEqual(new_networks, fake_lrp.networks)


class TestDelLRouterPortCommand(TestBaseCommand):

    def _test_lrouter_port_del_no_exist(self, if_exists=True):
        with mock.patch.object(idlutils, 'row_by_value',
                               side_effect=idlutils.RowNotFound):
            cmd = commands.DelLRouterPortCommand(
                self.ovn_api, 'fake-lrp', 'fake-lrouter', if_exists=if_exists)
            if if_exists:
                cmd.run_idl(self.transaction)
            else:
                self.assertRaises(RuntimeError, cmd.run_idl, self.transaction)

    def test_lrouter_port_no_exist_ignore(self):
        self._test_lrouter_port_del_no_exist(if_exists=True)

    def test_lrouter_port_no_exist_fail(self):
        self._test_lrouter_port_del_no_exist(if_exists=False)

    def test_lrouter_no_exist(self):
        with mock.patch.object(idlutils, 'row_by_value',
                               side_effect=[mock.ANY, idlutils.RowNotFound]):
            cmd = commands.DelLRouterPortCommand(
                self.ovn_api, 'fake-lrp', 'fake-lrouter', if_exists=True)
            self.assertRaises(RuntimeError, cmd.run_idl, self.transaction)

    def test_lrouter_port_del(self):
        fake_lrp = mock.MagicMock()
        fake_lrouter = fakes.FakeOvsdbRow.create_one_ovsdb_row(
            attrs={'ports': [fake_lrp]})
        self.ovn_api._tables['Logical_Router_Port'].rows[fake_lrp.uuid] = \
            fake_lrp
        with mock.patch.object(idlutils, 'row_by_value',
                               side_effect=[fake_lrp, fake_lrouter]):
            cmd = commands.DelLRouterPortCommand(
                self.ovn_api, fake_lrp.name, fake_lrouter.name, if_exists=True)
            cmd.run_idl(self.transaction)
            fake_lrouter.delvalue.assert_called_once_with('ports', fake_lrp)


class TestSetLRouterPortInLSwitchPortCommand(TestBaseCommand):

    def test_lswitch_port_no_exist_fail(self):
        with mock.patch.object(idlutils, 'row_by_value',
                               side_effect=idlutils.RowNotFound):
            cmd = commands.SetLRouterPortInLSwitchPortCommand(
                self.ovn_api, 'fake-lsp', 'fake-lrp', False, False, 'router')
            self.assertRaises(RuntimeError, cmd.run_idl, self.transaction)

    def test_lswitch_port_no_exist_do_not_fail(self):
        with mock.patch.object(idlutils, 'row_by_value',
                               side_effect=idlutils.RowNotFound):
            cmd = commands.SetLRouterPortInLSwitchPortCommand(
                self.ovn_api, 'fake-lsp', 'fake-lrp', False, True, 'router')
            cmd.run_idl(self.transaction)

    def test_lswitch_port_router_update(self):
        lrp_name = 'fake-lrp'
        fake_lsp = fakes.FakeOvsdbRow.create_one_ovsdb_row()
        with mock.patch.object(idlutils, 'row_by_value',
                               return_value=fake_lsp):
            cmd = commands.SetLRouterPortInLSwitchPortCommand(
                self.ovn_api, fake_lsp.name, lrp_name, True, True, 'router')
            cmd.run_idl(self.transaction)
            self.assertEqual({'router-port': lrp_name,
                              'nat-addresses': 'router',
                              'exclude-lb-vips-from-garp': 'true'},
                             fake_lsp.options)
            self.assertEqual('router', fake_lsp.type)
            self.assertEqual('router', fake_lsp.addresses)


class TestAddACLCommand(TestBaseCommand):

    def test_lswitch_no_exist(self, if_exists=True):
        with mock.patch.object(idlutils, 'row_by_value',
                               side_effect=idlutils.RowNotFound):
            cmd = commands.AddACLCommand(
                self.ovn_api, 'fake-lswitch', 'fake-lsp')
            self.assertRaises(RuntimeError, cmd.run_idl, self.transaction)

    def test_acl_add(self):
        fake_lswitch = fakes.FakeOvsdbRow.create_one_ovsdb_row()
        with mock.patch.object(idlutils, 'row_by_value',
                               return_value=fake_lswitch):
            fake_acl = fakes.FakeOvsdbRow.create_one_ovsdb_row()
            self.transaction.insert.return_value = fake_acl
            cmd = commands.AddACLCommand(
                self.ovn_api, fake_lswitch.name, 'fake-lsp', match='*')
            cmd.run_idl(self.transaction)
            self.transaction.insert.assert_called_once_with(
                self.ovn_api._tables['ACL'])
            fake_lswitch.addvalue.assert_called_once_with(
                'acls', fake_acl.uuid)
            self.assertEqual('*', fake_acl.match)


class TestDelACLCommand(TestBaseCommand):

    def _test_lswitch_no_exist(self, if_exists=True):
        with mock.patch.object(idlutils, 'row_by_value',
                               side_effect=idlutils.RowNotFound):
            cmd = commands.DelACLCommand(
                self.ovn_api, 'fake-lswitch', 'fake-lsp',
                if_exists=if_exists)
            if if_exists:
                cmd.run_idl(self.transaction)
            else:
                self.assertRaises(RuntimeError, cmd.run_idl, self.transaction)

    def test_lswitch_no_exist_ignore(self):
        self._test_lswitch_no_exist(if_exists=True)

    def test_lswitch_no_exist_fail(self):
        self._test_lswitch_no_exist(if_exists=False)

    def test_acl_del(self):
        fake_lsp_name = 'fake-lsp'
        fake_acl_del = fakes.FakeOvsdbRow.create_one_ovsdb_row(
            attrs={'external_ids': {'neutron:lport': fake_lsp_name}})
        fake_acl_save = mock.ANY
        fake_lswitch = fakes.FakeOvsdbRow.create_one_ovsdb_row(
            attrs={'acls': [fake_acl_del, fake_acl_save]})
        with mock.patch.object(idlutils, 'row_by_value',
                               return_value=fake_lswitch):
            cmd = commands.DelACLCommand(
                self.ovn_api, fake_lswitch.name, fake_lsp_name,
                if_exists=True)
            cmd.run_idl(self.transaction)
            fake_lswitch.delvalue.assert_called_once_with('acls', mock.ANY)


class TestAddStaticRouteCommand(TestBaseCommand):

    def test_lrouter_not_found(self):
        with mock.patch.object(idlutils, 'row_by_value',
                               side_effect=idlutils.RowNotFound):
            cmd = commands.AddStaticRouteCommand(self.ovn_api, 'fake-lrouter')
            self.assertRaises(RuntimeError, cmd.run_idl, self.transaction)
            self.transaction.insert.assert_not_called()

    def test_static_route_add(self):
        fake_lrouter = fakes.FakeOvsdbRow.create_one_ovsdb_row()
        with mock.patch.object(idlutils, 'row_by_value',
                               return_value=fake_lrouter):
            fake_static_route = fakes.FakeOvsdbRow.create_one_ovsdb_row()
            self.transaction.insert.return_value = fake_static_route
            cmd = commands.AddStaticRouteCommand(
                self.ovn_api, fake_lrouter.name,
                nexthop='40.0.0.100',
                ip_prefix='30.0.0.0/24')
            cmd.run_idl(self.transaction)
            self.transaction.insert.assert_called_once_with(
                self.ovn_api._tables['Logical_Router_Static_Route'])
            self.assertEqual('40.0.0.100', fake_static_route.nexthop)
            self.assertEqual('30.0.0.0/24', fake_static_route.ip_prefix)
            fake_lrouter.addvalue.assert_called_once_with(
                'static_routes', fake_static_route.uuid)


class TestDelStaticRoutesCommand(TestBaseCommand):

    def _test_lrouter_no_exist(self, if_exists=True):
        with mock.patch.object(idlutils, 'row_by_value',
                               side_effect=idlutils.RowNotFound):
            cmd = commands.DelStaticRoutesCommand(
                self.ovn_api, 'fake-lrouter',
                [('30.0.0.0/24', '40.0.0.100')],
                if_exists=if_exists)
            if if_exists:
                cmd.run_idl(self.transaction)
            else:
                self.assertRaises(RuntimeError, cmd.run_idl, self.transaction)

    def test_lrouter_no_exist_ignore(self):
        self._test_lrouter_no_exist(if_exists=True)

    def test_lrouter_no_exist_fail(self):
        self._test_lrouter_no_exist(if_exists=False)

    def test_static_route_del(self):
        fake_static_route1 = fakes.FakeOvsdbRow.create_one_ovsdb_row(
            attrs={'ip_prefix': '50.0.0.0/24', 'nexthop': '40.0.0.101'})
        fake_static_route2 = fakes.FakeOvsdbRow.create_one_ovsdb_row(
            attrs={'ip_prefix': '60.0.0.0/24', 'nexthop': '40.0.0.101'})
        fake_lrouter = fakes.FakeOvsdbRow.create_one_ovsdb_row(
            attrs={'static_routes': [fake_static_route1, fake_static_route2]})
        with mock.patch.object(idlutils, 'row_by_value',
                               return_value=fake_lrouter):
            cmd = commands.DelStaticRoutesCommand(
                self.ovn_api, fake_lrouter.name,
                [(fake_static_route1.ip_prefix, fake_static_route1.nexthop),
                 (fake_static_route2.ip_prefix, fake_static_route2.nexthop)],
                if_exists=True)
            cmd.run_idl(self.transaction)
            fake_lrouter.delvalue.assert_called_with(
                'static_routes', mock.ANY)

    def test_static_route_del_not_found(self):
        fake_static_route1 = fakes.FakeOvsdbRow.create_one_ovsdb_row(
            attrs={'ip_prefix': '50.0.0.0/24', 'nexthop': '40.0.0.101'})
        fake_static_route2 = fakes.FakeOvsdbRow.create_one_ovsdb_row(
            attrs={'ip_prefix': '60.0.0.0/24', 'nexthop': '70.0.0.101'})
        fake_lrouter = fakes.FakeOvsdbRow.create_one_ovsdb_row(
            attrs={'static_routes': [fake_static_route2]})
        with mock.patch.object(idlutils, 'row_by_value',
                               return_value=fake_lrouter):
            cmd = commands.DelStaticRoutesCommand(
                self.ovn_api, fake_lrouter.name,
                [(fake_static_route1.ip_prefix, fake_static_route1.nexthop)],
                if_exists=True)
            cmd.run_idl(self.transaction)
            fake_lrouter.delvalue.assert_not_called()
            self.assertEqual([mock.ANY], fake_lrouter.static_routes)


class TestUpdateChassisExtIdsCommand(TestBaseCommand):
    def setUp(self):
        super().setUp()
        self.ext_ids = {ovn_const.OVN_SG_EXT_ID_KEY: 'default'}

    def _test_chassis_extids_update_no_exist(self, if_exists=True):
        with mock.patch.object(idlutils, 'row_by_value',
                               side_effect=idlutils.RowNotFound):
            cmd = commands.UpdateChassisExtIdsCommand(
                self.ovn_api, 'fake-chassis', self.ext_ids,
                if_exists=if_exists)
            if if_exists:
                cmd.run_idl(self.transaction)
            else:
                self.assertRaises(RuntimeError, cmd.run_idl, self.transaction)

    def test_chassis_no_exist_ignore(self):
        self._test_chassis_extids_update_no_exist(if_exists=True)

    def test_chassis_no_exist_fail(self):
        self._test_chassis_extids_update_no_exist(if_exists=False)

    def test_chassis_extids_update(self):
        new_ext_ids = {ovn_const.OVN_SG_EXT_ID_KEY: 'default-new'}
        fake_chassis = fakes.FakeOvsdbRow.create_one_ovsdb_row(
            attrs={'external_ids': self.ext_ids})
        with mock.patch.object(idlutils, 'row_by_value',
                               return_value=fake_chassis):
            cmd = commands.UpdateChassisExtIdsCommand(
                self.ovn_api, fake_chassis.name,
                new_ext_ids, if_exists=True)
            cmd.run_idl(self.transaction)
            self.assertEqual(new_ext_ids, fake_chassis.external_ids)


class TestUpdatePortBindingExtIdsCommand(TestBaseCommand):
    def setUp(self):
        super().setUp()
        self.ext_ids = {ovn_const.OVN_SG_EXT_ID_KEY: 'default'}

    def _test_portbinding_extids_update_no_exist(self, if_exists=True):
        with mock.patch.object(idlutils, 'row_by_value',
                               side_effect=idlutils.RowNotFound):
            cmd = commands.UpdatePortBindingExtIdsCommand(
                self.ovn_api, 'fake-portbinding', self.ext_ids,
                if_exists=if_exists)
            if if_exists:
                cmd.run_idl(self.transaction)
            else:
                self.assertRaises(RuntimeError, cmd.run_idl, self.transaction)

    def test_portbinding_no_exist_ignore(self):
        self._test_portbinding_extids_update_no_exist(if_exists=True)

    def test_portbinding_no_exist_fail(self):
        self._test_portbinding_extids_update_no_exist(if_exists=False)

    def test_portbinding_extids_update(self):
        new_ext_ids = {ovn_const.OVN_SG_EXT_ID_KEY: 'default-new'}
        fake_portbinding = fakes.FakeOvsdbRow.create_one_ovsdb_row(
            attrs={'external_ids': self.ext_ids})
        with mock.patch.object(idlutils, 'row_by_value',
                               return_value=fake_portbinding):
            cmd = commands.UpdatePortBindingExtIdsCommand(
                self.ovn_api, fake_portbinding.name,
                new_ext_ids, if_exists=True)
            cmd.run_idl(self.transaction)
            self.assertEqual(new_ext_ids, fake_portbinding.external_ids)


class TestAddDHCPOptionsCommand(TestBaseCommand):

    def test_dhcp_options_exists(self):
        fake_ext_ids = {'subnet_id': 'fake-subnet-id',
                        'port_id': 'fake-port-id'}
        fake_dhcp_options = fakes.FakeOvsdbRow.create_one_ovsdb_row(
            attrs={'external_ids': fake_ext_ids})
        self.ovn_api._tables['DHCP_Options'].rows[fake_dhcp_options.uuid] = \
            fake_dhcp_options
        cmd = commands.AddDHCPOptionsCommand(
            self.ovn_api, fake_ext_ids['subnet_id'], fake_ext_ids['port_id'],
            may_exist=True, external_ids=fake_ext_ids)
        cmd.run_idl(self.transaction)
        self.transaction.insert.assert_not_called()
        self.assertEqual(fake_ext_ids, fake_dhcp_options.external_ids)

    def _test_dhcp_options_add(self, may_exist=True):
        fake_subnet_id = 'fake-subnet-id-' + str(may_exist)
        fake_port_id = 'fake-port-id-' + str(may_exist)
        fake_ext_ids1 = {'subnet_id': fake_subnet_id, 'port_id': fake_port_id}
        fake_dhcp_options1 = fakes.FakeOvsdbRow.create_one_ovsdb_row(
            attrs={'external_ids': fake_ext_ids1})
        self.ovn_api._tables['DHCP_Options'].rows[fake_dhcp_options1.uuid] = \
            fake_dhcp_options1
        fake_ext_ids2 = {'subnet_id': fake_subnet_id}
        fake_dhcp_options2 = fakes.FakeOvsdbRow.create_one_ovsdb_row(
            attrs={'external_ids': fake_ext_ids2})
        fake_dhcp_options3 = fakes.FakeOvsdbRow.create_one_ovsdb_row(
            attrs={'external_ids': {'subnet_id': 'nomatch'}})
        self.ovn_api._tables['DHCP_Options'].rows[fake_dhcp_options3.uuid] = \
            fake_dhcp_options3
        self.transaction.insert.return_value = fake_dhcp_options2
        cmd = commands.AddDHCPOptionsCommand(
            self.ovn_api, fake_ext_ids2['subnet_id'], may_exist=may_exist,
            external_ids=fake_ext_ids2)
        cmd.run_idl(self.transaction)
        self.transaction.insert.assert_called_once_with(
            self.ovn_api._tables['DHCP_Options'])
        self.assertEqual(fake_ext_ids2, fake_dhcp_options2.external_ids)

    def test_dhcp_options_add_may_exist(self):
        self._test_dhcp_options_add(may_exist=True)

    def test_dhcp_options_add_ignore_exists(self):
        self._test_dhcp_options_add(may_exist=False)

    def _test_dhcp_options_update_result(self, new_insert=False):
        fake_ext_ids = {'subnet_id': 'fake_subnet', 'port_id': 'fake_port'}
        fake_dhcp_opts = fakes.FakeOvsdbRow.create_one_ovsdb_row(
            attrs={'external_ids': fake_ext_ids})
        if new_insert:
            self.transaction.insert.return_value = fake_dhcp_opts
            self.transaction.get_insert_uuid = mock.Mock(
                return_value='fake-uuid')
        else:
            self.ovn_api._tables['DHCP_Options'].rows[fake_dhcp_opts.uuid] = \
                fake_dhcp_opts
            self.transaction.get_insert_uuid = mock.Mock(
                return_value=None)

        cmd = commands.AddDHCPOptionsCommand(
            self.ovn_api, fake_ext_ids['subnet_id'],
            port_id=fake_ext_ids['port_id'], may_exist=True,
            external_ids=fake_ext_ids)
        cmd.run_idl(self.transaction)
        cmd.post_commit(self.transaction)
        if new_insert:
            self.assertEqual('fake-uuid', cmd.result)
        else:
            self.assertEqual(fake_dhcp_opts.uuid, cmd.result)

    def test_dhcp_options_update_result_with_exist_row(self):
        self._test_dhcp_options_update_result(new_insert=False)

    def test_dhcp_options_update_result_with_new_row(self):
        self._test_dhcp_options_update_result(new_insert=True)


class TestDelDHCPOptionsCommand(TestBaseCommand):

    def _test_dhcp_options_del_no_exist(self, if_exists=True):
        cmd = commands.DelDHCPOptionsCommand(
            self.ovn_api, 'fake-dhcp-options', if_exists=if_exists)
        if if_exists:
            cmd.run_idl(self.transaction)
        else:
            self.assertRaises(RuntimeError, cmd.run_idl, self.transaction)

    def test_dhcp_options_no_exist_ignore(self):
        self._test_dhcp_options_del_no_exist(if_exists=True)

    def test_dhcp_options_no_exist_fail(self):
        self._test_dhcp_options_del_no_exist(if_exists=False)

    def test_dhcp_options_del(self):
        fake_dhcp_options = fakes.FakeOvsdbRow.create_one_ovsdb_row(
            attrs={'external_ids': {'subnet_id': 'fake-subnet-id'}})
        self.ovn_api._tables['DHCP_Options'].rows[fake_dhcp_options.uuid] = \
            fake_dhcp_options
        cmd = commands.DelDHCPOptionsCommand(
            self.ovn_api, fake_dhcp_options.uuid, if_exists=True)
        cmd.run_idl(self.transaction)
        fake_dhcp_options.delete.assert_called_once_with()


class TestAddNATRuleInLRouterCommand(TestBaseCommand):

    def test_add_nat_rule(self):
        fake_lrouter = fakes.FakeOvsdbRow.create_one_ovsdb_row()
        fake_nat_rule_1 = fakes.FakeOvsdbRow.create_one_ovsdb_row(
            attrs={'external_ip': '192.168.1.10',
                   'logical_ip': '10.0.0.4', 'type': 'dnat_and_snat'})
        fake_nat_rule_2 = fakes.FakeOvsdbRow.create_one_ovsdb_row(
            attrs={'external_ip': '192.168.1.8',
                   'logical_ip': '10.0.0.5', 'type': 'dnat_and_snat'})
        fake_lrouter.nat = [fake_nat_rule_1, fake_nat_rule_2]
        self.ovn_api._tables['NAT'].rows[fake_nat_rule_1.uuid] = \
            fake_nat_rule_1
        self.ovn_api._tables['NAT'].rows[fake_nat_rule_2.uuid] = \
            fake_nat_rule_2
        with mock.patch.object(idlutils, 'row_by_value',
                               return_value=fake_lrouter):
            cmd = commands.AddNATRuleInLRouterCommand(
                self.ovn_api, fake_lrouter.name)
            cmd.run_idl(self.transaction)
            self.transaction.insert.assert_called_once_with(
                self.ovn_api._tables['NAT'])
            # a UUID will have been appended
            self.assertEqual(3, len(fake_lrouter.nat))
            self.assertIn(fake_nat_rule_1, fake_lrouter.nat)
            self.assertIn(fake_nat_rule_2, fake_lrouter.nat)

    def test_add_nat_rule_with_persist_uuid(self):
        fake_lrouter = fakes.FakeOvsdbRow.create_one_ovsdb_row()
        fake_lrouter.nat = []
        nat_uuid = uuidutils.generate_uuid()
        with mock.patch.object(idlutils, 'row_by_value',
                               return_value=fake_lrouter), \
            mock.patch('neutron.common.ovn.utils.'
                   'ovs_persist_uuid_supported', return_value=True):
            cmd = commands.AddNATRuleInLRouterCommand(
                self.ovn_api, fake_lrouter.name, nat_uuid=nat_uuid)
            cmd.run_idl(self.transaction)
            self.transaction.insert.assert_called_once_with(
                self.ovn_api._tables['NAT'],
                new_uuid=uuid.UUID(nat_uuid), persist_uuid=True)

    def test_add_nat_rule_with_uuid_no_persist_support(self):
        fake_lrouter = fakes.FakeOvsdbRow.create_one_ovsdb_row()
        fake_lrouter.nat = []
        nat_uuid = uuidutils.generate_uuid()
        with mock.patch.object(idlutils, 'row_by_value',
                               return_value=fake_lrouter), \
            mock.patch('neutron.common.ovn.utils.'
                   'ovs_persist_uuid_supported', return_value=False):
            cmd = commands.AddNATRuleInLRouterCommand(
                self.ovn_api, fake_lrouter.name, nat_uuid=nat_uuid)
            cmd.run_idl(self.transaction)
            self.transaction.insert.assert_called_once_with(
                self.ovn_api._tables['NAT'])

    def test_add_nat_rule_no_lrouter_exist(self):
        with mock.patch.object(idlutils, 'row_by_value',
                               side_effect=idlutils.RowNotFound):
            cmd = commands.AddNATRuleInLRouterCommand(
                self.ovn_api, "fake-lrouter")
            self.assertRaises(RuntimeError, cmd.run_idl, self.transaction)


class TestDeleteNATRuleInLRouterCommand(TestBaseCommand):

    def test_delete_nat_rule(self):
        fake_lrouter = fakes.FakeOvsdbRow.create_one_ovsdb_row()
        fake_nat_rule_1 = fakes.FakeOvsdbRow.create_one_ovsdb_row(
            attrs={'external_ip': '192.168.1.10',
                   'logical_ip': '10.0.0.4', 'type': 'dnat_and_snat'})
        fake_nat_rule_2 = fakes.FakeOvsdbRow.create_one_ovsdb_row(
            attrs={'external_ip': '192.168.1.8',
                   'logical_ip': '10.0.0.5', 'type': 'dnat_and_snat'})
        fake_lrouter.nat = [fake_nat_rule_1, fake_nat_rule_2]
        self.ovn_api._tables['NAT'].rows[fake_nat_rule_1.uuid] = \
            fake_nat_rule_1
        self.ovn_api._tables['NAT'].rows[fake_nat_rule_2.uuid] = \
            fake_nat_rule_2
        with mock.patch.object(idlutils, 'row_by_value',
                               return_value=fake_lrouter):
            cmd = commands.DeleteNATRuleInLRouterCommand(
                self.ovn_api, fake_lrouter.name, fake_nat_rule_1.type,
                fake_nat_rule_1.logical_ip, fake_nat_rule_1.external_ip,
                False)
            cmd.run_idl(self.transaction)
            fake_nat_rule_1.delete.assert_called_once_with()
            self.assertEqual(1, len(fake_lrouter.nat))
            self.assertNotIn(fake_nat_rule_1, fake_lrouter.nat)
            self.assertIn(fake_nat_rule_2, fake_lrouter.nat)

            # run again with same arguments, should not remove anything
            fake_nat_rule_1.delete.reset_mock()
            cmd.run_idl(self.transaction)
            fake_nat_rule_1.delete.assert_not_called()
            self.assertEqual(1, len(fake_lrouter.nat))
            self.assertNotIn(fake_nat_rule_1, fake_lrouter.nat)
            self.assertIn(fake_nat_rule_2, fake_lrouter.nat)

    def _test_delete_nat_rule_no_lrouter_exist(self, if_exists=True):
        with mock.patch.object(idlutils, 'row_by_value',
                               side_effect=idlutils.RowNotFound):
            cmd = commands.DeleteNATRuleInLRouterCommand(
                self.ovn_api, "fake-lrouter", "fake-type", "fake-logical-ip",
                "fake-external-ip", if_exists=if_exists)
            if if_exists:
                cmd.run_idl(self.transaction)
            else:
                self.assertRaises(RuntimeError, cmd.run_idl, self.transaction)

    def test_delete_nat_rule_no_lrouter_exist_ignore(self):
        self._test_delete_nat_rule_no_lrouter_exist(if_exists=True)

    def test_delete_nat_rule_no_lrouter_exist_fail(self):
        self._test_delete_nat_rule_no_lrouter_exist(if_exists=False)


class TestSetNATRuleInLRouterCommand(TestBaseCommand):

    def test_set_nat_rule(self):
        fake_lrouter = fakes.FakeOvsdbRow.create_one_ovsdb_row()
        fake_nat_rule_1 = fakes.FakeOvsdbRow.create_one_ovsdb_row(
            attrs={'external_ip': '192.168.1.10',
                   'logical_ip': '10.0.0.4', 'type': 'dnat_and_snat'})
        fake_nat_rule_2 = fakes.FakeOvsdbRow.create_one_ovsdb_row(
            attrs={'external_ip': '192.168.1.8',
                   'logical_ip': '10.0.0.5', 'type': 'dnat_and_snat'})
        fake_lrouter.nat = [fake_nat_rule_1, fake_nat_rule_2]
        self.ovn_api._tables['NAT'].rows[fake_nat_rule_1.uuid] = \
            fake_nat_rule_1
        self.ovn_api._tables['NAT'].rows[fake_nat_rule_2.uuid] = \
            fake_nat_rule_2
        with mock.patch.object(idlutils, 'row_by_value',
                               return_value=fake_lrouter):
            cmd = commands.SetNATRuleInLRouterCommand(
                self.ovn_api, fake_lrouter.name, fake_nat_rule_1.uuid,
                logical_ip='10.0.0.10')
            cmd.run_idl(self.transaction)
            self.assertEqual('10.0.0.10', fake_nat_rule_1.logical_ip)
            self.assertEqual('10.0.0.5', fake_nat_rule_2.logical_ip)

    def test_set_nat_rule_no_lrouter_exist(self):
        with mock.patch.object(idlutils, 'row_by_value',
                               side_effect=idlutils.RowNotFound):
            cmd = commands.SetNATRuleInLRouterCommand(
                self.ovn_api, "fake-lrouter", "fake-uuid",
                logical_ip='fake-ip')
            self.assertRaises(RuntimeError, cmd.run_idl, self.transaction)


class TestCheckRevisionNumberCommand(TestBaseCommand):
    def setUp(self):
        super().setUp()
        self.fip = {'name': 'floating-ip', 'revision_number': 3}
        self.fip_old_rev = {'name': 'floating-ip', 'revision_number': 1}
        self.nat_rule = fakes.FakeOvsdbRow.create_one_ovsdb_row(
            attrs={'external_ip': '192.168.1.10', 'name': 'floating-ip',
                   'logical_ip': '10.0.0.4', 'type': 'dnat_and_snat',
                   'external_ids':
                       {ovn_const.OVN_FIP_EXT_ID_KEY: 'floating-ip',
                        ovn_const.OVN_REV_NUM_EXT_ID_KEY: 3}})
        bad_nat_rule = fakes.FakeOvsdbRow.create_one_ovsdb_row(
            attrs={'external_ip': '192.168.1.11',
                   'logical_ip': '10.0.0.5', 'type': 'bad_type'})
        self.ovn_api._tables['NAT'].rows[self.nat_rule.uuid] = self.nat_rule
        self.ovn_api._tables['NAT'].rows[bad_nat_rule.uuid] = bad_nat_rule

        self.subnet = fakes.FakeOvsdbRow.create_one_ovsdb_row(
            attrs={'external_ids': {'subnet_id': 'mysubnet'}})
        bad_subnet = fakes.FakeOvsdbRow.create_one_ovsdb_row(
            attrs={'external_ids': {'port_id': 'fake-lsp'}})
        self.ovn_api._tables['DHCP_Options'].rows[self.subnet.uuid] = \
            self.subnet
        self.ovn_api._tables['DHCP_Options'].rows[bad_subnet.uuid] = \
            bad_subnet

    def _test_check_revision_number(
            self, name='fake-name', resource='fake-resource',
            resource_type=ovn_const.TYPE_NETWORKS, if_exists=True,
            revision_conflict=False):
        with mock.patch.object(self.ovn_api, "is_col_present",
                               return_value=True):
            with mock.patch.object(self.ovn_api, 'lookup',
                                   side_effect=idlutils.RowNotFound):
                cmd = commands.CheckRevisionNumberCommand(
                    self.ovn_api, name, resource, resource_type,
                    if_exists=if_exists)
                if if_exists:
                    cmd.run_idl(self.transaction)
                elif revision_conflict:
                    self.assertRaises(ovn_exc.RevisionConflict, cmd.run_idl,
                                      self.transaction)
                else:
                    self.assertRaises(RuntimeError, cmd.run_idl,
                                      self.transaction)

    def test_check_revision_number_no_exist_ignore(self):
        self._test_check_revision_number(if_exists=True)

    def test_check_revision_number_no_exist_fail(self):
        self._test_check_revision_number(if_exists=False)

    def _test_check_revision_number_fip(self, resource, lookup_result=None,
                                        db_find_rows_result=None,
                                        if_exists=True,
                                        revision_conflict=False):
        self.ovn_api.lookup.return_value = lookup_result
        mock_cmd = mock.Mock()
        mock_cmd.execute.return_value = db_find_rows_result or []
        self.ovn_api.db_find_rows.return_value = mock_cmd
        cmd = commands.CheckRevisionNumberCommand(
            self.ovn_api, resource['name'], resource,
            ovn_const.TYPE_FLOATINGIPS, if_exists=if_exists)
        if revision_conflict:
            self.assertRaises(ovn_exc.RevisionConflict, cmd.run_idl,
                              self.transaction)
        elif not lookup_result and not db_find_rows_result and not if_exists:
            self.assertRaises(RuntimeError, cmd.run_idl, self.transaction)
        else:
            cmd.run_idl(self.transaction)

    def test_check_revision_number_floating_ip_lookup(self):
        self._test_check_revision_number_fip(
            self.fip, lookup_result=self.nat_rule)

    def test_check_revision_number_floating_ip_db_find_rows(self):
        self._test_check_revision_number_fip(
            self.fip, db_find_rows_result=[self.nat_rule])

    def test_check_revision_number_floating_ip_not_found(self):
        self._test_check_revision_number_fip(
            {'name': 'fip-not-found', 'revision_number': 3},
            if_exists=False)

    def test_check_revision_number_floating_ip_revision_conflict(self):
        self._test_check_revision_number_fip(
            self.fip_old_rev, lookup_result=self.nat_rule,
            revision_conflict=True)

    def test_check_revision_number_subnet(self):
        self._test_check_revision_number(
            name=self.subnet['name'], resource=self.subnet,
            resource_type=ovn_const.TYPE_SUBNETS, if_exists=True)

    def test_check_revision_number_subnet_not_found(self):
        self._test_check_revision_number(
            name='subnet-not-found', resource=self.subnet,
            resource_type=ovn_const.TYPE_SUBNETS, if_exists=False)


class TestDeleteLRouterExtGwCommand(TestBaseCommand):

    def test_delete_lrouter_extgw_routes(self):
        fake_route_1 = fakes.FakeOvsdbRow.create_one_ovsdb_row(
            attrs={'ip_prefix': n_const.IPv4_ANY, 'nexthop': '10.0.0.1',
                   'external_ids': {ovn_const.OVN_ROUTER_IS_EXT_GW: True}})
        fake_route_2 = fakes.FakeOvsdbRow.create_one_ovsdb_row(
            attrs={'ip_prefix': '50.0.0.0/24', 'nexthop': '40.0.0.101'})
        fake_lrouter = fakes.FakeOvsdbRow.create_one_ovsdb_row(
            attrs={'static_routes': [fake_route_1, fake_route_2],
                   'nat': []})
        self.ovn_api.get_lrouter_gw_ports.return_value = []
        with mock.patch.object(self.ovn_api, "is_col_present",
                               return_value=True):
            with mock.patch.object(idlutils, 'row_by_value',
                                   return_value=fake_lrouter):
                cmd = commands.DeleteLRouterExtGwCommand(
                    self.ovn_api, fake_lrouter.name, False)
                cmd.run_idl(self.transaction)
                fake_lrouter.delvalue.assert_called_once_with(
                    'static_routes', fake_route_1)

    def test_delete_lrouter_multiple_extgw_routes(self):
        fake_route_1 = fakes.FakeOvsdbRow.create_one_ovsdb_row(
            attrs={'ip_prefix': n_const.IPv4_ANY, 'nexthop': '10.0.0.1',
                   'external_ids': {ovn_const.OVN_ROUTER_IS_EXT_GW: True},
                   'output_port': '1'})
        fake_route_2 = fakes.FakeOvsdbRow.create_one_ovsdb_row(
            attrs={'ip_prefix': n_const.IPv4_ANY, 'nexthop': '10.0.0.1',
                   'external_ids': {ovn_const.OVN_ROUTER_IS_EXT_GW: True},
                   'output_port': '2'})
        fake_route_3 = fakes.FakeOvsdbRow.create_one_ovsdb_row(
            attrs={'ip_prefix': '50.0.0.0/24', 'nexthop': '40.0.0.101'})
        fake_lrouter = fakes.FakeOvsdbRow.create_one_ovsdb_row(
            attrs={'static_routes': [fake_route_1, fake_route_2, fake_route_3],
                   'nat': []})
        # Where the real IDL keeps track of removals without changing the
        # in-memory table data structure, the FakeOvsdbRow by default does
        # change the in-memory List of fake rows.
        #
        # The DeleteLRouterExtGwCommand iterates over this list, and iterating
        # over a data structure you are removing items from leads to undefined
        # behavior.
        #
        # For the purpose of this test we do not need to remove the items, only
        # check whether the expected calls were made or not.
        fake_lrouter.delvalue.side_effect = None

        self.ovn_api.get_lrouter_gw_ports.return_value = []
        with mock.patch.object(self.ovn_api, "is_col_present",
                               return_value=True):
            with mock.patch.object(idlutils, 'row_by_value',
                                   return_value=fake_lrouter):
                cmd = commands.DeleteLRouterExtGwCommand(
                    self.ovn_api, fake_lrouter.name, False)
                cmd.run_idl(self.transaction)
                fake_lrouter.delvalue.assert_has_calls([
                    mock.call('static_routes', fake_route_1),
                    mock.call('static_routes', fake_route_2),
                ])
                self.assertEqual(
                    2,
                    fake_lrouter.delvalue.call_count)

    def test_delete_lrouter_extgw_nat(self):
        fake_nat_1 = fakes.FakeOvsdbRow.create_one_ovsdb_row(
            attrs={'external_ip': '192.168.1.10',
                   'logical_ip': '10.0.0.4', 'type': 'snat'})
        fake_nat_2 = fakes.FakeOvsdbRow.create_one_ovsdb_row(
            attrs={'external_ip': '192.168.1.8',
                   'logical_ip': '10.0.0.5', 'type': 'badtype'})
        fake_lrouter = fakes.FakeOvsdbRow.create_one_ovsdb_row(
            attrs={'nat': [fake_nat_1, fake_nat_2],
                   'static_routes': []})
        self.ovn_api.get_lrouter_gw_ports.return_value = []
        with mock.patch.object(self.ovn_api, "is_col_present",
                               return_value=True):
            with mock.patch.object(idlutils, 'row_by_value',
                                   return_value=fake_lrouter):
                cmd = commands.DeleteLRouterExtGwCommand(
                    self.ovn_api, fake_lrouter.name, False)
                cmd.run_idl(self.transaction)
                fake_lrouter.delvalue.assert_called_once_with(
                    'nat', fake_nat_1)

    def test_delete_lrouter_extgw_ports(self):
        port_id = 'fake-port-id'
        fake_lrp = fakes.FakeOvsdbRow.create_one_ovsdb_row(
            attrs={'gateway_chassis': ['fake_gwc']})
        fake_lrouter = fakes.FakeOvsdbRow.create_one_ovsdb_row(
            attrs={'ports': [fake_lrp], 'static_routes': [], 'nat': []})
        self.ovn_api.get_lrouter_gw_ports.return_value = [fake_lrp]
        with mock.patch.object(self.ovn_api, "is_col_present",
                               return_value=True):
            with mock.patch.object(idlutils, 'row_by_value',
                                   side_effect=[fake_lrouter, port_id]):
                cmd = commands.DeleteLRouterExtGwCommand(
                    self.ovn_api, fake_lrouter.name, False)
                cmd.run_idl(self.transaction)
                fake_lrouter.delvalue.assert_called_once_with(
                    'ports', fake_lrp)

    def test_delete_lrouter_extgw_ports_not_found(self):
        fake_lrouter = fakes.FakeOvsdbRow.create_one_ovsdb_row(
            attrs={'static_routes': [], 'nat': []})
        self.ovn_api.get_lrouter_gw_ports.return_value = []
        with mock.patch.object(self.ovn_api, "is_col_present",
                               return_value=True):
            with mock.patch.object(idlutils, 'row_by_value',
                                   side_effect=[fake_lrouter]):
                cmd = commands.DeleteLRouterExtGwCommand(
                    self.ovn_api, fake_lrouter.name, False)
                cmd.run_idl(self.transaction)
                self.ovn_api.get_lrouter_gw_ports.assert_called_once_with(
                    fake_lrouter.name)
                fake_lrouter.delvalue.assert_not_called()

    def _test_delete_lrouter_no_lrouter_exist(self, if_exists=True):
        with mock.patch.object(self.ovn_api, "is_col_present",
                               return_value=True):
            with mock.patch.object(idlutils, 'row_by_value',
                                   side_effect=idlutils.RowNotFound):
                cmd = commands.DeleteLRouterExtGwCommand(
                    self.ovn_api, "fake-lrouter", if_exists=if_exists)
                if if_exists:
                    cmd.run_idl(self.transaction)
                else:
                    self.assertRaises(RuntimeError, cmd.run_idl,
                                      self.transaction)

    def test_delete_lrouter_no_lrouter_exist_ignore(self):
        self._test_delete_lrouter_no_lrouter_exist(if_exists=True)

    def test_delete_no_lrouter_exist_fail(self):
        self._test_delete_lrouter_no_lrouter_exist(if_exists=False)


class TestScheduleUnhostedGatewaysCommand(TestBaseCommand):

    @staticmethod
    def _insert_hcg(table):
        fake_hcg = fakes.FakeOvsdbRow.create_one_ovsdb_row()
        table.rows[fake_hcg.uuid] = fake_hcg
        fake_hcg.ha_chassis = []
        fake_hcg.addvalue = lambda _, item: fake_hcg.ha_chassis.append(item)
        return fake_hcg

    def test_schedule_unhosted_gateways_rebalances_lower_prios(self):
        unhosted_gws = ['lrp-foo-1', 'lrp-foo-2', 'lrp-foo-3']
        port_physnets = {k[len(ovn_const.LRP_PREFIX):]: 'physnet1'
                         for k in unhosted_gws}
        # we skip chasiss2 here since we assume it has been removed
        chassis_mappings = {
            'chassis1': ['physnet1'],
            'chassis3': ['physnet1'],
            'chassis4': ['physnet1'],
        }
        chassis = ['chassis1', 'chassis3', 'chassis4']
        sb_api = mock.MagicMock()
        plugin = mock.MagicMock()
        plugin.scheduler.select.side_effect = [
            ['chassis1', 'chassis4', 'chassis3'],
            ['chassis4', 'chassis3', 'chassis1'],
            ['chassis4', 'chassis3', 'chassis1'],
        ]
        self.transaction.insert.side_effect = self._insert_hcg

        expected_mapping = {
            'lrp-foo-1': ['chassis1', 'chassis4', 'chassis3'],
            'lrp-foo-2': ['chassis4', 'chassis3', 'chassis1'],
            'lrp-foo-3': ['chassis4', 'chassis3', 'chassis1'],
        }

        with mock.patch.object(
                self.ovn_api,
                'get_gateway_chassis_binding',
                side_effect=[
                    ['chassis1', 'chassis2', 'chassis3', 'chassis4'],
                    ['chassis2', 'chassis4', 'chassis3', 'chassis1'],
                    ['chassis4', 'chassis3', 'chassis1', 'chassis2'],
                ]):
            for g_name in unhosted_gws:
                lrouter_port = mock.MagicMock()
                with mock.patch.object(self.ovn_api, 'lookup',
                                       side_effect=[lrouter_port, None]):
                    with mock.patch.object(idlutils, 'row_by_value',
                                           side_effect=idlutils.RowNotFound):
                        cmd = commands.ScheduleUnhostedGatewaysCommand(
                            self.ovn_api, g_name, sb_api, plugin,
                            port_physnets, chassis, chassis_mappings, [])
                        cmd.run_idl(self.transaction)

                        ch_prio = []
                        hcg = self.ovn_api._tables['HA_Chassis_Group'].rows[
                            lrouter_port.ha_chassis_group]
                        for ha_chassis in hcg.ha_chassis:
                            ch_prio.append((ha_chassis.chassis_name,
                                            ha_chassis.priority))

                        ch_prio = sorted(ch_prio, key=lambda item: item[1],
                                         reverse=True)
                        ch_name = [ch for ch, _ in ch_prio]
                        self.assertEqual(expected_mapping[g_name], ch_name)


class _SamplingRow:
    """Minimal IDL row: unset columns raise AttributeError like new rows."""

    def __init__(self, **columns):
        self.uuid = uuid.uuid4()
        self.verified = set()
        for col, value in columns.items():
            setattr(self, col, value)

    def verify(self, column):
        self.verified.add(column)

    def setkey(self, column, key, value):
        # Like the IDL, setting a key also works on a column of a new row.
        if not hasattr(self, column):
            setattr(self, column, {})
        getattr(self, column)[key] = value

    def delkey(self, column, key):
        getattr(self, column).pop(key, None)

    def delvalue(self, column, value):
        getattr(self, column).remove(value)

    def delete(self):
        self.deleted = True


class _SamplingTable:
    def __init__(self):
        self.rows = {}

    def add(self, row):
        self.rows[row.uuid] = row
        return row


class _SamplingNb:
    def __init__(self):
        self.tables = {name: _SamplingTable() for name in (
            'Sampling_App', 'Sample_Collector', 'Sample', 'Port_Group')}

    def lookup(self, table, name):
        for row in self.tables[table].rows.values():
            if row.name == name:
                return row
        raise idlutils.RowNotFound(table=table, col='name', match=name)


class _SamplingTxn:
    def __init__(self, nb):
        self.nb = nb
        self.inserted = []

    def insert(self, table):
        row = table.add(_SamplingRow())
        self.inserted.append(row)
        return row


class TestSamplingCommandBase(base.BaseTestCase):

    def setUp(self):
        super().setUp()
        self.nb = _SamplingNb()
        self.txn = _SamplingTxn(self.nb)
        self.config = sampling.SamplingConfig(
            app_new_id=11, app_est_id=12, collector_id=13,
            collector_set_id=1000, probability=65535)

    def _add(self, table, **columns):
        return self.nb.tables[table].add(_SamplingRow(**columns))

    def _rows(self, table):
        return list(self.nb.tables[table].rows.values())

    def _owned_collector(self, collector_id=13):
        return self._add('Sample_Collector', id=collector_id,
                         name=ovn_const.OVN_SAMPLE_COLLECTOR_NAME,
                         probability=65535, set_id=1000,
                         external_ids=sampling.owner_external_ids())


class TestEnsureAclSamplingResourcesCommand(TestSamplingCommandBase):

    def _run(self):
        cmd = commands.EnsureAclSamplingResourcesCommand(self.nb, self.config)
        cmd.run_idl(self.txn)
        return cmd.result

    def test_create(self):
        result = self._run()
        apps = {a.type: a for a in self._rows('Sampling_App')}
        self.assertEqual({ovn_const.OVN_SAMPLING_APP_ACL_NEW: 11,
                          ovn_const.OVN_SAMPLING_APP_ACL_EST: 12},
                         {t: a.id for t, a in apps.items()})
        for app in apps.values():
            self.assertTrue(sampling.is_owned_row(app))
        collector, = self._rows('Sample_Collector')
        self.assertEqual(collector.uuid, result)
        self.assertEqual((13, 65535, 1000),
                         (collector.id, collector.probability,
                          collector.set_id))
        self.assertEqual(ovn_const.OVN_SAMPLE_COLLECTOR_NAME, collector.name)
        self.assertTrue(sampling.is_owned_row(collector))

    def test_idempotent(self):
        self._run()
        self.txn.inserted = []
        result = self._run()
        self.assertEqual([], self.txn.inserted)
        self.assertEqual(self._rows('Sample_Collector')[0].uuid, result)

    def test_update_owned_rows_in_place(self):
        app = self._add('Sampling_App', type='acl-new', id=99,
                        external_ids=sampling.owner_external_ids())
        collector = self._owned_collector(collector_id=50)
        collector.probability = 10
        self.assertEqual(collector.uuid, self._run())
        self.assertEqual(11, app.id)
        self.assertEqual((13, 65535), (collector.id, collector.probability))
        self.assertIn('id', app.verified)
        self.assertEqual(1, len(self._rows('Sample_Collector')))

    def test_foreign_app_type(self):
        self._add('Sampling_App', type='acl-new', id=11, external_ids={})
        self.assertRaises(ovn_exc.OVNSamplingResourceConflict, self._run)

    def test_foreign_app_id(self):
        self._add('Sampling_App', type='drop', id=12, external_ids={})
        self.assertRaises(ovn_exc.OVNSamplingResourceConflict, self._run)

    def test_swap_owned_app_ids(self):
        new = self._add('Sampling_App', type='acl-new', id=12,
                        external_ids=sampling.owner_external_ids())
        est = self._add('Sampling_App', type='acl-est', id=11,
                        external_ids=sampling.owner_external_ids())
        self._run()
        self.assertEqual((11, 12), (new.id, est.id))

    def test_extra_owned_collectors_are_reported(self):
        first = self._owned_collector()
        extra = self._owned_collector(collector_id=14)
        with mock.patch.object(commands.LOG, 'warning') as warn:
            self.assertEqual(first.uuid, self._run())
        warn.assert_called_once()
        self.assertEqual([extra.uuid], warn.call_args[0][1]['extra'])
        self.assertIn('external_ids', extra.verified)

    def test_foreign_collector_id(self):
        self._add('Sample_Collector', id=13, name='other', probability=1,
                  set_id=1, external_ids={})
        self.assertRaises(ovn_exc.OVNSamplingResourceConflict, self._run)


class TestSetPortGroupAclSamplingCommand(TestSamplingCommandBase):

    def setUp(self):
        super().setUp()
        self.collector = self._owned_collector()
        self.pg = self._add('Port_Group', name='pg_sg1', acls=[])

    def _acl(self, action, log=False, label=0, **columns):
        acl = _SamplingRow(action=action, log=log, label=label,
                           sample_new=[], sample_est=[], external_ids={},
                           **columns)
        self.pg.acls.append(acl)
        return acl

    def _run(self, actions, collector_id=13, port_group='pg_sg1',
             remove_unlogged_drop_acls=False):
        cmd = commands.SetPortGroupAclSamplingCommand(
            self.nb, port_group, actions, collector_id,
            remove_unlogged_drop_acls=remove_unlogged_drop_acls)
        cmd.run_idl(self.txn)
        return cmd.result

    def _sample(self, refs):
        # References are rows before the command runs and UUIDs after it.
        if not refs:
            return None
        ref, = refs
        if isinstance(ref, _SamplingRow):
            return ref
        return self.nb.tables['Sample'].rows[ref]

    def _md(self, acl, stage):
        sample = self._sample(getattr(acl, sampling.STAGE_ACL_COLUMN[stage]))
        return sample.metadata if sample else None

    def _make_owned(self, acl, stage, sample):
        setattr(acl, sampling.STAGE_ACL_COLUMN[stage], [sample])
        acl.external_ids[sampling.STAGE_ACL_EXT_ID_KEY[stage]] = str(
            sample.metadata)

    def _owned_sample(self, metadata):
        return self._add('Sample', metadata=metadata,
                         collectors=[self.collector])

    def _commit(self):
        # Replace the UUID references set by the command with rows, as the
        # IDL does after the transaction commits.
        for acl in self.pg.acls:
            for stage in sampling.STAGES:
                column = sampling.STAGE_ACL_COLUMN[stage]
                refs = getattr(acl, column)
                rows = self.nb.tables['Sample'].rows
                setattr(acl, column, [rows.get(r, r) for r in refs])
        for sample in self._rows('Sample'):
            sample.collectors = [
                self.nb.tables['Sample_Collector'].rows.get(c, c)
                for c in sample.collectors]

    def test_all_events_stateful(self):
        rule1 = self._acl(ovn_const.ACL_ACTION_ALLOW_RELATED)
        rule2 = self._acl(ovn_const.ACL_ACTION_ALLOW_RELATED)
        drop = self._acl(ovn_const.ACL_ACTION_DROP)
        result = self._run({ovn_const.ACL_ACTION_ALLOW_RELATED,
                            ovn_const.ACL_ACTION_DROP})
        self.assertEqual({'conflicts': [], 'attached': 5, 'detached': 0},
                         result)
        # One Sample per stage and observation action, shared by the ACLs.
        self.assertEqual(3, len(self._rows('Sample')))
        self.assertEqual(self._md(rule1, 'new'), self._md(rule2, 'new'))
        self.assertEqual(self._md(rule1, 'est'), self._md(rule2, 'est'))
        self.assertEqual(3, len({self._md(rule1, 'new'),
                                 self._md(rule1, 'est'),
                                 self._md(drop, 'new')}))
        self.assertIsNone(self._md(drop, 'est'))
        self.assertEqual(
            str(self._md(rule1, 'new')),
            rule1.external_ids[ovn_const.OVN_ACL_SAMPLE_NEW_EXT_ID_KEY])
        for sample in self._rows('Sample'):
            self.assertEqual([self.collector.uuid], sample.collectors)
        self.assertIn('acls', self.pg.verified)
        self.assertIn('sample_new', rule1.verified)

    def test_stateless_and_accept_only(self):
        rule = self._acl(ovn_const.ACL_ACTION_ALLOW_STATELESS)
        drop = self._acl(ovn_const.ACL_ACTION_DROP)
        self._run({ovn_const.ACL_ACTION_ALLOW_STATELESS})
        self.assertIsNotNone(self._md(rule, 'new'))
        self.assertIsNone(self._md(rule, 'est'))
        self.assertIsNone(self._md(drop, 'new'))
        self.assertEqual(1, len(self._rows('Sample')))

    def test_repeated_run_keeps_identity(self):
        rule = self._acl(ovn_const.ACL_ACTION_ALLOW_RELATED)
        actions = {ovn_const.ACL_ACTION_ALLOW_RELATED}
        self._run(actions)
        self._commit()
        before = (self._md(rule, 'new'), self._md(rule, 'est'))
        self.txn.inserted = []
        result = self._run(actions)
        self.assertEqual(0, result['attached'])
        self.assertEqual([], self.txn.inserted)
        self.assertEqual(before, (self._md(rule, 'new'),
                                  self._md(rule, 'est')))

    def test_new_acl_reuses_existing_sample(self):
        rule1 = self._acl(ovn_const.ACL_ACTION_ALLOW_RELATED)
        sample = self._owned_sample(1234)
        self._make_owned(rule1, 'new', sample)
        rule2 = self._acl(ovn_const.ACL_ACTION_ALLOW_STATELESS)
        self._run({ovn_const.ACL_ACTION_ALLOW_STATELESS,
                   ovn_const.ACL_ACTION_ALLOW_RELATED})
        self.assertEqual(1234, self._md(rule2, 'new'))
        # The est stage of rule1 was missing and gets a new Sample.
        self.assertEqual(2, len(self._rows('Sample')))

    def test_converge_to_most_common_metadata(self):
        acls = [self._acl(ovn_const.ACL_ACTION_ALLOW_STATELESS)
                for _ in range(3)]
        common = self._owned_sample(20)
        other = self._owned_sample(10)
        self._make_owned(acls[0], 'new', common)
        self._make_owned(acls[1], 'new', common)
        self._make_owned(acls[2], 'new', other)
        result = self._run({ovn_const.ACL_ACTION_ALLOW_STATELESS})
        self.assertEqual(1, result['attached'])
        self.assertEqual([20, 20, 20], [self._md(a, 'new') for a in acls])

    def test_detach(self):
        rule = self._acl(ovn_const.ACL_ACTION_ALLOW_RELATED)
        new = self._owned_sample(1)
        est = self._owned_sample(2)
        self._make_owned(rule, 'new', new)
        self._make_owned(rule, 'est', est)
        result = self._run(set(), collector_id=None)
        self.assertEqual({'conflicts': [], 'attached': 0, 'detached': 2},
                         result)
        self.assertEqual(([], []), (rule.sample_new, rule.sample_est))
        self.assertEqual({}, rule.external_ids)
        # The ownership decision is guarded against concurrent changes.
        for sample in (new, est):
            self.assertEqual({'metadata', 'collectors'}, sample.verified)
        self.assertIn('external_ids', self.collector.verified)

    def test_detach_only_actions_no_longer_requested(self):
        rule = self._acl(ovn_const.ACL_ACTION_ALLOW_STATELESS)
        drop = self._acl(ovn_const.ACL_ACTION_DROP)
        self._make_owned(rule, 'new', self._owned_sample(1))
        self._make_owned(drop, 'new', self._owned_sample(2))
        self._run({ovn_const.ACL_ACTION_ALLOW_STATELESS})
        self.assertEqual(1, self._md(rule, 'new'))
        self.assertEqual([], drop.sample_new)

    def test_foreign_reference_left_unchanged(self):
        rule = self._acl(ovn_const.ACL_ACTION_ALLOW_STATELESS)
        foreign = self._add('Sample', metadata=77,
                            collectors=[self.collector])
        rule.sample_new = [foreign]
        result = self._run(set(), collector_id=None)
        self.assertEqual([(rule.uuid, 'new')], result['conflicts'])
        self.assertEqual([foreign], rule.sample_new)
        result = self._run({ovn_const.ACL_ACTION_ALLOW_STATELESS})
        self.assertEqual([(rule.uuid, 'new')], result['conflicts'])
        self.assertEqual([foreign], rule.sample_new)
        self.assertNotIn(ovn_const.OVN_ACL_SAMPLE_NEW_EXT_ID_KEY,
                         rule.external_ids)

    def test_foreign_reference_raises_when_required(self):
        rule = self._acl(ovn_const.ACL_ACTION_ALLOW_STATELESS)
        stale = self._acl(ovn_const.ACL_ACTION_DROP)
        foreign = self._add('Sample', metadata=77,
                            collectors=[self.collector])
        rule.sample_new = [foreign]
        stale.sample_new = [foreign]
        cmd = commands.SetPortGroupAclSamplingCommand(
            self.nb, 'pg_sg1', {ovn_const.ACL_ACTION_ALLOW_STATELESS}, 13,
            raise_on_conflict=True)
        self.assertRaises(ovn_exc.OVNSamplingResourceConflict,
                          cmd.run_idl, self.txn)
        # A foreign reference on a stage that is not required is only
        # reported.
        cmd = commands.SetPortGroupAclSamplingCommand(
            self.nb, 'pg_sg1', {ovn_const.ACL_ACTION_DROP}, 13,
            raise_on_conflict=True)
        self.assertRaises(ovn_exc.OVNSamplingResourceConflict,
                          cmd.run_idl, self.txn)
        stale.sample_new = []
        cmd = commands.SetPortGroupAclSamplingCommand(
            self.nb, 'pg_sg1', {ovn_const.ACL_ACTION_DROP}, 13,
            raise_on_conflict=True)
        cmd.run_idl(self.txn)
        self.assertEqual([(rule.uuid, 'new')], cmd.result['conflicts'])
        self.assertIsNotNone(self._md(stale, 'new'))

    def test_stale_record_removed(self):
        rule = self._acl(ovn_const.ACL_ACTION_ALLOW_STATELESS)
        rule.external_ids[ovn_const.OVN_ACL_SAMPLE_NEW_EXT_ID_KEY] = '5'
        self._run(set(), collector_id=None)
        self.assertEqual({}, rule.external_ids)

    def test_label_of_logged_acl(self):
        logged = self._acl(ovn_const.ACL_ACTION_ALLOW_STATELESS, log=True,
                           label=99)
        unlogged = self._acl(ovn_const.ACL_ACTION_ALLOW_STATELESS)
        self._run({ovn_const.ACL_ACTION_ALLOW_STATELESS})
        self.assertEqual(self._md(logged, 'new'), logged.label)
        self.assertEqual(0, unlogged.label)

    def test_acl_inserted_in_transaction(self):
        # Rows inserted earlier in the transaction have unset columns.
        acl = _SamplingRow(action=ovn_const.ACL_ACTION_DROP)
        self.pg.acls.append(acl)
        self._run({ovn_const.ACL_ACTION_DROP})
        self.assertIsNotNone(self._md(acl, 'new'))

    def _sg_drop_acl(self, log=False):
        return self._acl(ovn_const.ACL_ACTION_DROP, log=log,
                         priority=ovn_const.ACL_PRIORITY_LOG_DROP)

    def test_remove_unlogged_drop_acls(self):
        unlogged = self._sg_drop_acl()
        owned = self._sg_drop_acl()
        sample = self._owned_sample(5)
        self._make_owned(owned, 'new', sample)
        logged = self._sg_drop_acl(log=True)
        rule = self._acl(ovn_const.ACL_ACTION_DROP, priority=1002)
        result = self._run(set(), collector_id=None,
                           remove_unlogged_drop_acls=True)
        self.assertEqual([logged, rule], self.pg.acls)
        self.assertTrue(unlogged.deleted)
        self.assertTrue(owned.deleted)
        self.assertFalse(hasattr(logged, 'deleted'))
        self.assertEqual(0, result['detached'])
        # The decision is guarded against concurrent changes.
        for column in ('log', 'external_ids', 'sample_new', 'sample_est'):
            self.assertIn(column, unlogged.verified)
        self.assertEqual({'metadata', 'collectors'}, sample.verified)
        self.assertIn('acls', self.pg.verified)

    def test_remove_unlogged_drop_acls_keeps_foreign_reference(self):
        acl = self._sg_drop_acl()
        foreign_collector = self._add('Sample_Collector', id=200,
                                      external_ids={})
        foreign = self._add('Sample', metadata=77,
                            collectors=[foreign_collector])
        acl.sample_new = [foreign]
        result = self._run(set(), collector_id=None,
                           remove_unlogged_drop_acls=True)
        self.assertEqual([acl], self.pg.acls)
        self.assertFalse(hasattr(acl, 'deleted'))
        self.assertEqual([(acl.uuid, 'new')], result['conflicts'])
        self.assertEqual([foreign], acl.sample_new)

    def test_unlogged_drop_acls_kept_by_default(self):
        acl = self._sg_drop_acl()
        self._run(set(), collector_id=None)
        self.assertEqual([acl], self.pg.acls)

    def test_missing_collector(self):
        self._acl(ovn_const.ACL_ACTION_DROP)
        self.assertRaises(RuntimeError, self._run,
                          {ovn_const.ACL_ACTION_DROP}, collector_id=99)

    def test_missing_port_group(self):
        result = self._run({ovn_const.ACL_ACTION_DROP},
                           port_group='missing')
        self.assertEqual({'conflicts': [], 'attached': 0, 'detached': 0},
                         result)
