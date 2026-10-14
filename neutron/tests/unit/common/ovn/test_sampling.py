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

import types
from unittest import mock
import uuid

from oslo_config import cfg

from neutron.common.ovn import constants as ovn_const
from neutron.common.ovn import exceptions as ovn_exc
from neutron.common.ovn import sampling
from neutron.conf.services import logging as log_cfg
from neutron.tests import base


def _row(**columns):
    columns.setdefault('uuid', uuid.uuid4())
    return types.SimpleNamespace(**columns)


class TestSamplingConfig(base.BaseTestCase):

    def setUp(self):
        super().setUp()
        log_cfg.register_ovn_acl_sampling_opts()
        self.conf = cfg.CONF.network_log

    def _enable(self, **overrides):
        values = {'ovn_acl_sampling': True,
                  'ovn_acl_sampling_app_new_id': 11,
                  'ovn_acl_sampling_app_est_id': 12,
                  'ovn_acl_sampling_collector_id': 13,
                  'ovn_acl_sampling_collector_set_id': 1000,
                  'ovn_acl_sampling_probability': 65535}
        values.update(overrides)
        for name, value in values.items():
            cfg.CONF.set_override(name, value, group='network_log')

    def test_disabled_by_default(self):
        self.assertIsNone(sampling.SamplingConfig.from_conf(self.conf))

    def test_enabled(self):
        self._enable()
        config = sampling.SamplingConfig.from_conf(self.conf)
        self.assertEqual(
            sampling.SamplingConfig(app_new_id=11, app_est_id=12,
                                    collector_id=13, collector_set_id=1000,
                                    probability=65535),
            config)

    def test_enabled_missing_option(self):
        self._enable(ovn_acl_sampling_collector_set_id=None,
                     ovn_acl_sampling_probability=None)
        exc = self.assertRaises(ValueError,
                                sampling.SamplingConfig.from_conf, self.conf)
        self.assertIn('ovn_acl_sampling_collector_set_id', str(exc))
        self.assertIn('ovn_acl_sampling_probability', str(exc))

    def test_enabled_same_app_ids(self):
        self._enable(ovn_acl_sampling_app_est_id=11)
        self.assertRaises(ValueError,
                          sampling.SamplingConfig.from_conf, self.conf)

    def test_option_ranges(self):
        self.assertRaises(ValueError, cfg.CONF.set_override,
                          'ovn_acl_sampling_app_new_id', 256,
                          group='network_log')
        self.assertRaises(ValueError, cfg.CONF.set_override,
                          'ovn_acl_sampling_probability', 0,
                          group='network_log')


class TestSamplingHelpers(base.BaseTestCase):

    def test_stages_for_acl_action(self):
        self.assertEqual(
            (sampling.STAGE_NEW, sampling.STAGE_EST),
            sampling.stages_for_acl_action(
                ovn_const.ACL_ACTION_ALLOW_RELATED))
        for action in (ovn_const.ACL_ACTION_ALLOW_STATELESS,
                       ovn_const.ACL_ACTION_ALLOW,
                       ovn_const.ACL_ACTION_DROP,
                       ovn_const.ACL_ACTION_REJECT):
            self.assertEqual((sampling.STAGE_NEW,),
                             sampling.stages_for_acl_action(action))
        self.assertEqual((), sampling.stages_for_acl_action('pass'))

    def test_observation_action(self):
        self.assertEqual(sampling.OBSERVE_ALLOW, sampling.observation_action(
            ovn_const.ACL_ACTION_ALLOW_STATELESS))
        self.assertEqual(sampling.OBSERVE_DROP, sampling.observation_action(
            ovn_const.ACL_ACTION_REJECT))
        self.assertIsNone(sampling.observation_action('pass'))

    def test_is_owned_row(self):
        self.assertTrue(sampling.is_owned_row(
            _row(external_ids=sampling.owner_external_ids())))
        self.assertFalse(sampling.is_owned_row(_row(external_ids={})))
        # Rows inserted in the current transaction without external_ids.
        self.assertFalse(sampling.is_owned_row(_row()))

    def test_recorded_metadata(self):
        key = ovn_const.OVN_ACL_SAMPLE_NEW_EXT_ID_KEY
        self.assertEqual(42, sampling.recorded_metadata(
            _row(external_ids={key: '42'}), sampling.STAGE_NEW))
        self.assertIsNone(sampling.recorded_metadata(
            _row(external_ids={key: '42'}), sampling.STAGE_EST))
        for value in ('x', '0', str(2 ** 32), 42, mock.Mock()):
            self.assertIsNone(sampling.recorded_metadata(
                _row(external_ids={key: value}), sampling.STAGE_NEW))
        self.assertIsNone(sampling.recorded_metadata(
            _row(), sampling.STAGE_NEW))

    def test_classify_attachment(self):
        key = ovn_const.OVN_ACL_SAMPLE_NEW_EXT_ID_KEY
        owned = _row()
        other = _row()
        sample = _row(metadata=7, collectors=[owned])

        def acl(ref, recorded=None):
            ext_ids = {key: recorded} if recorded else {}
            return _row(sample_new=ref, external_ids=ext_ids)

        owned_uuids = {owned.uuid}
        self.assertEqual(
            sampling.ATTACHMENT_NONE, sampling.classify_attachment(
                acl([]), sampling.STAGE_NEW, owned_uuids))
        self.assertEqual(
            sampling.ATTACHMENT_NONE, sampling.classify_attachment(
                acl([], '7'), sampling.STAGE_NEW, owned_uuids))
        self.assertEqual(
            sampling.ATTACHMENT_OWNED, sampling.classify_attachment(
                acl([sample], '7'), sampling.STAGE_NEW, owned_uuids))
        # No ownership record.
        self.assertEqual(
            sampling.ATTACHMENT_FOREIGN, sampling.classify_attachment(
                acl([sample]), sampling.STAGE_NEW, owned_uuids))
        # The reference changed after Neutron recorded it.
        self.assertEqual(
            sampling.ATTACHMENT_FOREIGN, sampling.classify_attachment(
                acl([sample], '8'), sampling.STAGE_NEW, owned_uuids))
        # The Sample uses a collector that is not owned by Neutron.
        foreign_sample = _row(metadata=7, collectors=[owned, other])
        self.assertEqual(
            sampling.ATTACHMENT_FOREIGN, sampling.classify_attachment(
                acl([foreign_sample], '7'), sampling.STAGE_NEW, owned_uuids))

    def test_choose_metadata(self):
        self.assertIsNone(sampling.choose_metadata([]))
        self.assertIsNone(sampling.choose_metadata(None))
        self.assertEqual(5, sampling.choose_metadata([9, 5, 5]))
        self.assertEqual(5, sampling.choose_metadata([9, 5]))

    def test_allocate_metadata(self):
        with mock.patch('secrets.SystemRandom.randint',
                        side_effect=[3, 3, 4]):
            self.assertEqual(4, sampling.allocate_metadata({3}))

    def test_allocate_metadata_exhausted(self):
        with mock.patch('secrets.SystemRandom.randint', return_value=3):
            self.assertRaises(ovn_exc.OVNSamplingMetadataExhausted,
                              sampling.allocate_metadata, {3}, attempts=2)

    def test_allocate_metadata_range(self):
        value = sampling.allocate_metadata(set())
        self.assertGreaterEqual(value, sampling.MIN_METADATA)
        self.assertLessEqual(value, sampling.MAX_METADATA)
