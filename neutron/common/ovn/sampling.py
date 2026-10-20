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

"""Helpers for OVN ACL sampling managed by the network log service.

An OVN ACL can reference one Sample for new connections (``sample_new``) and
one for established traffic (``sample_est``). Neutron allocates one Sample
per security group, connection stage and observation action, and shares it
between the ACLs and network logs of that security group. The helpers in
this module do not access OVSDB by themselves; the OVSDB commands use them on
rows read inside an IDL transaction.
"""

import collections
import dataclasses
import secrets

from neutron_lib.services.logapi import constants as log_const

from neutron._i18n import _
from neutron.common.ovn import constants as ovn_const
from neutron.common.ovn import exceptions as ovn_exc

STAGE_NEW = 'new'
STAGE_EST = 'est'
STAGES = (STAGE_NEW, STAGE_EST)

STAGE_ACL_COLUMN = {
    STAGE_NEW: 'sample_new',
    STAGE_EST: 'sample_est',
}
STAGE_ACL_EXT_ID_KEY = {
    STAGE_NEW: ovn_const.OVN_ACL_SAMPLE_NEW_EXT_ID_KEY,
    STAGE_EST: ovn_const.OVN_ACL_SAMPLE_EST_EXT_ID_KEY,
}

# Observation actions. They are part of the Sample identity so that the allow
# and drop observations of one security group do not share an identifier.
OBSERVE_ALLOW = 'allow'
OBSERVE_DROP = 'drop'

_ACL_ACTION_OBSERVATION = {
    ovn_const.ACL_ACTION_ALLOW_RELATED: OBSERVE_ALLOW,
    ovn_const.ACL_ACTION_ALLOW_STATELESS: OBSERVE_ALLOW,
    ovn_const.ACL_ACTION_ALLOW: OBSERVE_ALLOW,
    ovn_const.ACL_ACTION_DROP: OBSERVE_DROP,
    ovn_const.ACL_ACTION_REJECT: OBSERVE_DROP,
}

# Port Group external_ids key of the Sample metadata of each identity.
PG_SAMPLE_EXT_ID_KEY = {
    (OBSERVE_ALLOW, STAGE_NEW): ovn_const.OVN_PG_SAMPLE_ALLOW_NEW_EXT_ID_KEY,
    (OBSERVE_ALLOW, STAGE_EST): ovn_const.OVN_PG_SAMPLE_ALLOW_EST_EXT_ID_KEY,
    (OBSERVE_DROP, STAGE_NEW): ovn_const.OVN_PG_SAMPLE_DROP_NEW_EXT_ID_KEY,
}

MIN_METADATA = 1
MAX_METADATA = 2 ** 32 - 1
METADATA_ALLOCATION_ATTEMPTS = 16

# Northbound columns required to manage ACL sampling, as (table, column).
REQUIRED_COLUMNS = (
    ('Sampling_App', 'type'),
    ('Sample_Collector', 'set_id'),
    ('Sample', 'metadata'),
    ('ACL', 'sample_new'),
    ('ACL', 'sample_est'),
    ('ACL', 'label'),
)


@dataclasses.dataclass(frozen=True)
class SamplingConfig:
    """Operator supplied identifiers of the Neutron sampling resources."""

    app_new_id: int
    app_est_id: int
    collector_id: int
    collector_set_id: int
    probability: int

    @classmethod
    def from_conf(cls, conf):
        """Return the configuration, or None if sampling is disabled.

        :param conf: the ``network_log`` configuration group.
        :raises ValueError: if sampling is enabled but the configuration is
            incomplete or inconsistent.
        """
        if not conf.ovn_acl_sampling:
            return None
        values = {
            'app_new_id': conf.ovn_acl_sampling_app_new_id,
            'app_est_id': conf.ovn_acl_sampling_app_est_id,
            'collector_id': conf.ovn_acl_sampling_collector_id,
            'collector_set_id': conf.ovn_acl_sampling_collector_set_id,
            'probability': conf.ovn_acl_sampling_probability,
        }
        missing = sorted(k for k, v in values.items() if v is None)
        if missing:
            raise ValueError(
                _('ovn_acl_sampling is enabled but the following options '
                  'are not set: %s') % ', '.join(
                    'ovn_acl_sampling_' + m for m in missing))
        if values['app_new_id'] == values['app_est_id']:
            raise ValueError(
                _('ovn_acl_sampling_app_new_id and '
                  'ovn_acl_sampling_app_est_id must be different'))
        return cls(**values)


def owner_external_ids():
    return {ovn_const.OVN_DEVICE_OWNER_EXT_ID_KEY: log_const.LOGGING_PLUGIN}


def is_owned_row(row):
    """Return True if a Sampling_App or Sample_Collector row is ours."""
    ext_ids = _column(row, 'external_ids', {})
    return (ext_ids.get(ovn_const.OVN_DEVICE_OWNER_EXT_ID_KEY) ==
            log_const.LOGGING_PLUGIN)


def observation_action(acl_action):
    """Map an OVN ACL action to an observation action, or None."""
    return _ACL_ACTION_OBSERVATION.get(acl_action)


def stages_for_acl_action(acl_action):
    """Return the sampling stages an ACL with this action can use.

    Established-stage samples are only emitted for traffic that OVN commits
    to conntrack, which applies to stateful ``allow-related`` ACLs.
    Stateless allowing ACLs and drop ACLs are sampled on the new stage.
    """
    if acl_action == ovn_const.ACL_ACTION_ALLOW_RELATED:
        return STAGES
    if acl_action in _ACL_ACTION_OBSERVATION:
        return (STAGE_NEW,)
    return ()


def _column(row, column, default):
    # Rows inserted in the current IDL transaction raise AttributeError for
    # columns that have not been written yet.
    try:
        return getattr(row, column)
    except AttributeError:
        return default


def recorded_metadata(acl, stage):
    """Return the Sample metadata Neutron recorded on an ACL stage."""
    value = _column(acl, 'external_ids', {}).get(STAGE_ACL_EXT_ID_KEY[stage])
    if not isinstance(value, str):
        return None
    try:
        metadata = int(value)
    except (TypeError, ValueError):
        return None
    if MIN_METADATA <= metadata <= MAX_METADATA:
        return metadata
    return None


def referenced_sample(acl, stage):
    """Return the Sample row referenced by an ACL stage, or None."""
    ref = _column(acl, STAGE_ACL_COLUMN[stage], [])
    if isinstance(ref, (list, tuple)):
        return ref[0] if ref else None
    return ref


def sample_metadata(sample):
    metadata = _column(sample, 'metadata', None)
    if isinstance(metadata, (list, tuple)):
        return metadata[0] if metadata else None
    return metadata


ATTACHMENT_NONE = 'none'
ATTACHMENT_OWNED = 'owned'
ATTACHMENT_FOREIGN = 'foreign'


def sample_collector_uuids(sample):
    return [c.uuid for c in _column(sample, 'collectors', [])]


def classify_attachment(acl, stage, owned_collector_uuids):
    """Classify the sample reference of an ACL stage.

    :param owned_collector_uuids: UUIDs of the Sample_Collector rows owned
        by Neutron.
    :returns: ``ATTACHMENT_NONE`` if the stage has no reference,
        ``ATTACHMENT_OWNED`` if Neutron recorded the reference and it points
        to a Sample with the recorded metadata that uses one Neutron
        collector, and ``ATTACHMENT_FOREIGN`` otherwise.
    """
    sample = referenced_sample(acl, stage)
    if sample is None:
        return ATTACHMENT_NONE
    recorded = recorded_metadata(acl, stage)
    collectors = sample_collector_uuids(sample)
    if (recorded is not None and sample_metadata(sample) == recorded and
            len(collectors) == 1 and
            collectors[0] in owned_collector_uuids):
        return ATTACHMENT_OWNED
    return ATTACHMENT_FOREIGN


def choose_metadata(candidates):
    """Choose the metadata of one Sample identity from existing references.

    Normally all the ACLs of a Sample identity reference the same Sample. If
    an interrupted update left several values, the most common one is kept
    and the smallest value wins a tie, so repeated runs converge.
    """
    if not candidates:
        return None
    counts = collections.Counter(candidates)
    return min(counts, key=lambda md: (-counts[md], md))


def allocate_metadata(used, attempts=METADATA_ALLOCATION_ATTEMPTS):
    """Return a random Sample metadata value that is not in ``used``.

    :raises OVNSamplingMetadataExhausted: if no free value was found.
    """
    rand = secrets.SystemRandom()
    for _attempt in range(attempts):
        metadata = rand.randint(MIN_METADATA, MAX_METADATA)
        if metadata not in used:
            return metadata
    raise ovn_exc.OVNSamplingMetadataExhausted(attempts=attempts)
