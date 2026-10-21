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

from unittest import mock

from neutron_lib.api.definitions import logging_output_type as output_apidef
from neutron_lib.callbacks import events
from neutron_lib.callbacks import priority_group
from neutron_lib import exceptions
from neutron_lib import fixture
from neutron_lib.services.logapi import constants as log_const

from neutron.services.logapi.common import exceptions as log_exc
from neutron.services.logapi.drivers import base as log_driver_base
from neutron.services.logapi.drivers import manager as driver_mgr
from neutron.tests.unit.services.logapi import base


class TestGetParameter(base.BaseLogTestCase):

    def test__get_param_missing_parameter(self):
        kwargs = {'context': mock.sentinel.context}
        self.assertRaises(log_exc.LogapiDriverException,
                          driver_mgr._get_param,
                          args=[], kwargs=kwargs,
                          name='log_obj', index=1)
        self.assertRaises(log_exc.LogapiDriverException,
                          driver_mgr._get_param,
                          args=[mock.sentinel.context], kwargs={},
                          name='log_obj', index=1)
        self.assertRaises(log_exc.LogapiDriverException,
                          driver_mgr._get_param,
                          args=[], kwargs={'log_obj': mock.sentinel.log_obj},
                          name='context', index=0)


class TestLogDriversManagerBase(base.BaseLogTestCase):

    def setUp(self):
        super().setUp()
        self.config_parse()
        self.setup_coreplugin(load_plugins=False)

    @staticmethod
    def _create_manager_with_drivers(drivers_details):
        for name, driver_details in drivers_details.items():
            class LogDriver(log_driver_base.DriverBase):
                @property
                def is_loaded(self):
                    return driver_details['is_loaded']

                @property
                def available_output_types(self):
                    return driver_details.get(
                        'available_output_types',
                        self.supported_output_types)

            LogDriver(name,
                      driver_details.get('vif_types', []),
                      driver_details.get('vnic_types', []),
                      driver_details.get('supported_logging_types', []),
                      requires_rpc=driver_details.get('requires_rpc', False),
                      supported_output_types=driver_details.get(
                          'supported_output_types'))

        return driver_mgr.LoggingServiceDriverManager()


class TestLogDriversManagerMulti(TestLogDriversManagerBase):
    """Test calls happen to all drivers"""

    def test_driver_manager_empty_with_no_drivers(self):
        driver_manager = self._create_manager_with_drivers({})
        self.assertEqual(0, len(driver_manager.drivers))

    def test_driver_manager_empty_with_no_loaded_drivers(self):
        driver_manager = self._create_manager_with_drivers(
            {'driver-A': {'is_loaded': False}})
        self.assertEqual(0, len(driver_manager.drivers))

    def test_driver_manager_with_one_loaded_driver(self):
        driver_manager = self._create_manager_with_drivers(
            {'driver-A': {'is_loaded': True}})
        self.assertEqual(1, len(driver_manager.drivers))

    def test_driver_manager_with_two_loaded_drivers(self):
        driver_manager = self._create_manager_with_drivers(
            {'driver-A': {'is_loaded': True},
             'driver-B': {'is_loaded': True}})
        self.assertEqual(2, len(driver_manager.drivers))


class TestLogDriversManagerLoggingTypes(TestLogDriversManagerBase):
    """Test supported logging types"""

    def test_available_logging_types(self):
        driver_manager = self._create_manager_with_drivers(
            {'driver-A': {'is_loaded': True,
                          'supported_logging_types': ['security_group']},
             'driver-B': {'is_loaded': True,
                          'supported_logging_types':
                              ['security_group', 'firewall']}
             })
        self.assertEqual({'security_group', 'firewall'},
                         driver_manager.supported_logging_types)


class TestLogDriversOutputTypes(TestLogDriversManagerBase):
    """Test log output type support and dispatch"""

    DRIVERS = {
        'packet-only': {'is_loaded': True,
                        'supported_logging_types': ['security_group']},
        'sampling': {'is_loaded': True,
                     'supported_logging_types': ['security_group', 'snat'],
                     'supported_output_types': [output_apidef.PACKET_LOG,
                                                output_apidef.FLOW_SAMPLE]},
    }

    @staticmethod
    def _log(output_type):
        return mock.Mock(output_type=output_type)

    def test_default_output_types(self):
        driver_manager = self._create_manager_with_drivers(
            {'driver-A': {'is_loaded': True,
                          'supported_logging_types': ['security_group']}})
        self.assertEqual({output_apidef.PACKET_LOG},
                         driver_manager.supported_output_types(
                             'security_group'))
        self.assertEqual(set(),
                         driver_manager.supported_output_types('snat'))

    def test_output_types_intersection(self):
        driver_manager = self._create_manager_with_drivers(self.DRIVERS)
        # Both drivers support security_group, only one supports sampling.
        self.assertEqual({output_apidef.PACKET_LOG},
                         driver_manager.supported_output_types(
                             'security_group'))
        self.assertEqual({output_apidef.PACKET_LOG,
                          output_apidef.FLOW_SAMPLE},
                         driver_manager.supported_output_types('snat'))

    def test_unavailable_output_still_dispatched(self):
        drivers = {'sampling': dict(
            self.DRIVERS['sampling'],
            available_output_types=[output_apidef.PACKET_LOG])}
        driver_manager = self._create_manager_with_drivers(drivers)
        # Not advertised, so new logs of the output are rejected...
        self.assertEqual({output_apidef.PACKET_LOG},
                         driver_manager.supported_output_types(
                             'security_group'))
        # ...but existing logs can still be disabled and deleted.
        flow_log = self._log(output_apidef.FLOW_SAMPLE)
        with mock.patch.object(log_driver_base.DriverBase,
                               'delete_log') as delete_log:
            driver_manager.call('delete_log', mock.sentinel.ctx, flow_log)
        delete_log.assert_called_once_with(mock.sentinel.ctx, flow_log)

    def test_call_dispatches_by_output_type(self):
        driver_manager = self._create_manager_with_drivers(self.DRIVERS)
        drivers = {d.name: d for d in driver_manager.drivers}
        with mock.patch.object(log_driver_base.DriverBase,
                               'create_log') as create_log:
            flow_log = self._log(output_apidef.FLOW_SAMPLE)
            driver_manager.call('create_log', mock.sentinel.ctx, flow_log)
            create_log.assert_called_once_with(mock.sentinel.ctx, flow_log)
            create_log.reset_mock()

            packet_log = self._log(output_apidef.PACKET_LOG)
            driver_manager.call('create_log', mock.sentinel.ctx,
                                log_obj=packet_log)
            self.assertEqual(2, create_log.call_count)
            create_log.reset_mock()

            driver_manager.call('resource_update', mock.sentinel.ctx,
                                [flow_log, packet_log])
        self.assertEqual(2, len(drivers))

    def test_call_narrows_log_lists(self):
        driver_manager = self._create_manager_with_drivers(self.DRIVERS)
        flow_log = self._log(output_apidef.FLOW_SAMPLE)
        packet_log = self._log(output_apidef.PACKET_LOG)
        calls = []
        with mock.patch.object(
                log_driver_base.DriverBase, 'resource_update',
                side_effect=lambda ctx, logs: calls.append(list(logs))):
            driver_manager.call('resource_update', mock.sentinel.ctx,
                                [flow_log, packet_log])
        self.assertEqual(2, len(calls))
        self.assertIn([packet_log], calls)
        self.assertIn([flow_log, packet_log], calls)

    def test_rpc_only_for_packet_logs(self):
        driver_manager = self._create_manager_with_drivers(
            {'agent': {'is_loaded': True, 'requires_rpc': True,
                       'supported_logging_types': ['security_group']}})
        rpc = mock.Mock()
        driver_manager._logging_rpc = rpc
        packet_log = self._log(output_apidef.PACKET_LOG)
        flow_log = self._log(output_apidef.FLOW_SAMPLE)
        with mock.patch.object(log_driver_base.DriverBase, 'create_log'):
            driver_manager.call('create_log', mock.sentinel.ctx, packet_log)
            rpc.create_log.assert_called_once_with(mock.sentinel.ctx,
                                                   packet_log)
            rpc.reset_mock()
            driver_manager.call('create_log', mock.sentinel.ctx, flow_log)
            rpc.create_log.assert_not_called()
            driver_manager.call('resource_update', mock.sentinel.ctx,
                                [flow_log, packet_log])
            rpc.resource_update.assert_called_once_with(
                mock.sentinel.ctx, [packet_log])


class TestLogDriversCalls(TestLogDriversManagerBase):
    """Test log driver calls"""

    def setUp(self):
        super().setUp()
        self.driver_manager = self._create_manager_with_drivers(
            {'driver-A': {'is_loaded': True}})

    def test_implemented_call_methods(self):
        for method in log_const.LOG_CALL_METHODS:
            with mock.patch.object(log_driver_base.DriverBase, method) as \
                    method_fnc:
                context = mock.sentinel.context
                log_obj = mock.sentinel.log_obj
                self.driver_manager.call(
                    method, context=context, log_objs=[log_obj])
                method_fnc.assert_called_once_with(
                    context=context, log_objs=[log_obj])

    def test_not_implemented_call_methods(self):
        context = mock.sentinel.context
        log_obj = mock.sentinel.log_obj
        self.assertRaises(exceptions.DriverCallError, self.driver_manager.call,
                          'wrong_method', context=context, log_objs=[log_obj])


class TestHandleResourceCallback(TestLogDriversManagerBase):
    """Test handle resource callback"""

    def setUp(self):
        super().setUp()
        self._cb_mgr = mock.Mock()
        self.useFixture(fixture.CallbackRegistryFixture(
            callback_manager=self._cb_mgr))
        self.driver_manager = driver_mgr.LoggingServiceDriverManager()

    def test_subscribe_resources_cb(self):

        class FakeResourceCB1(driver_mgr.ResourceCallBackBase):
            def handle_event(self, resource, event, trigger, **kwargs):
                pass

        class FakeResourceCB2(driver_mgr.ResourceCallBackBase):
            def handle_event(self, resource, event, trigger, **kwargs):
                pass

        driver_mgr.RESOURCE_CB_CLASS_MAP = {'fake_resource1': FakeResourceCB1,
                                            'fake_resource2': FakeResourceCB2}

        self.driver_manager._setup_resources_cb_handle()

        fake_resource_cb1 = FakeResourceCB1(
            'fake_resource1', self.driver_manager.call)
        fake_resource_cb2 = FakeResourceCB2(
            'fake_resource2', self.driver_manager.call)
        assert_calls = [
            mock.call(
                fake_resource_cb1.handle_event,
                'fake_resource1', events.AFTER_CREATE,
                priority_group.PRIORITY_DEFAULT, False),
            mock.call(
                fake_resource_cb1.handle_event,
                'fake_resource1', events.AFTER_UPDATE,
                priority_group.PRIORITY_DEFAULT, False),
            mock.call(
                fake_resource_cb1.handle_event,
                'fake_resource1', events.AFTER_DELETE,
                priority_group.PRIORITY_DEFAULT, False),
            mock.call(
                fake_resource_cb2.handle_event,
                'fake_resource2', events.AFTER_CREATE,
                priority_group.PRIORITY_DEFAULT, False),
            mock.call(
                fake_resource_cb2.handle_event,
                'fake_resource2', events.AFTER_UPDATE,
                priority_group.PRIORITY_DEFAULT, False),
            mock.call(
                fake_resource_cb2.handle_event,
                'fake_resource2', events.AFTER_DELETE,
                priority_group.PRIORITY_DEFAULT, False),
        ]
        self._cb_mgr.subscribe.assert_has_calls(assert_calls)
