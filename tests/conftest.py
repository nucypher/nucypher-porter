import os
from typing import Iterable, List, Optional, Tuple
from unittest.mock import MagicMock

import maya
import prometheus_client
import pytest
from click.testing import CliRunner
from eth_typing import ChecksumAddress
from eth_utils import to_checksum_address
from nucypher.blockchain.eth.actors import Operator
from nucypher.blockchain.eth.agents import (
    ContractAgency,
    CoordinatorAgent,
    StakingProvidersReservoir,
    TACoChildApplicationAgent,
)
from nucypher.blockchain.eth.interfaces import BlockchainInterfaceFactory
from nucypher.blockchain.eth.models import Coordinator, Ferveo
from nucypher.blockchain.eth.registry import ContractRegistry
from nucypher.blockchain.eth.signers.software import Web3Signer
from nucypher.characters.lawful import Enrico, Ursula
from nucypher.crypto.ferveo import dkg
from nucypher.crypto.powers import DecryptingPower, RitualisticPower
from nucypher.network.nodes import Learner, Teacher
from nucypher.policy.conditions.lingo import ConditionLingo
from nucypher.utilities.logging import GlobalLoggerSettings
from nucypher_core import HRAC, Address, ThresholdMessageKit, TreasureMap
from nucypher_core.ferveo import DkgPublicKey, Validator
from prometheus_flask_exporter import PrometheusMetrics

from porter.emitters import WebEmitter
from porter.main import Porter
from tests.constants import (
    MOCK_ETH_PROVIDER_URI,
    TEMPORARY_DOMAIN,
    TEST_ETH_PROVIDER_URI,
    TESTERCHAIN_CHAIN_ID,
)
from tests.mock.interfaces import MockBlockchain
from tests.utils.middleware import MockRestMiddleware, _TestMiddlewareClient
from tests.utils.registry import MockRegistrySource, mock_registry_sources

# Crash on server error by default
WebEmitter._crash_on_error_default = True
Learner._DEBUG_MODE = False

pytest_plugins = [
    'pytest-nucypher',  # Includes external fixtures module from nucypher
]


def pytest_addhooks(pluginmanager):
    pluginmanager.set_blocked("ape_test")


def pytest_collection_modifyitems(config, items):
    #
    # Handle Log Level
    #

    log_level_name = config.getoption("--log-level", "info", skip=True)

    GlobalLoggerSettings.stop_sentry_logging()
    GlobalLoggerSettings.set_log_level(log_level_name)
    GlobalLoggerSettings.start_text_file_logging()
    GlobalLoggerSettings.start_json_file_logging()


@pytest.fixture(scope='session')
def monkeysession():
    from _pytest.monkeypatch import MonkeyPatch

    mpatch = MonkeyPatch()
    yield mpatch
    mpatch.undo()


@pytest.fixture(scope="module")
def monkeymodule():
    from _pytest.monkeypatch import MonkeyPatch

    mpatch = MonkeyPatch()
    yield mpatch
    mpatch.undo()


@pytest.fixture(scope='module')
def click_runner():
    runner = CliRunner()
    yield runner


@pytest.fixture(scope='module')
def get_random_checksum_address():
    def _get_random_checksum_address():
        canonical_address = os.urandom(20)
        checksum_address = to_checksum_address(canonical_address)
        return checksum_address

    return _get_random_checksum_address


@pytest.fixture(scope="module")
def testerchain(mock_testerchain, module_mocker) -> MockBlockchain:
    def always_use_mock(*a, **k):
        return mock_testerchain

    module_mocker.patch.object(
        BlockchainInterfaceFactory, "get_interface", always_use_mock
    )
    return mock_testerchain


@pytest.fixture(scope="module")
def test_registry(module_mocker):
    with mock_registry_sources(mocker=module_mocker):
        mock_source = MockRegistrySource(domain=TEMPORARY_DOMAIN)
        registry = ContractRegistry(source=mock_source)
        yield registry


@pytest.fixture(scope="module", autouse=True)
def staking_providers(accounts, test_registry, monkeymodule):
    def faked(self, *args, **kwargs):
        return accounts.staking_provider_account(
            accounts.ursulas_accounts.index(self.transacting_power.account)
        )

    Operator.get_staking_provider_address = faked
    return accounts.staking_providers_accounts


@pytest.fixture(scope="module", autouse=True)
def mock_contract_agency():
    from tests.mock.agents import MockContractAgency

    # Monkeypatch # TODO: Use better tooling for this monkeypatch?
    get_agent = ContractAgency.get_agent
    get_agent_by_name = ContractAgency.get_agent_by_contract_name
    ContractAgency.get_agent = MockContractAgency.get_agent
    ContractAgency.get_agent_by_contract_name = (
        MockContractAgency.get_agent_by_contract_name
    )

    # Test
    yield MockContractAgency()

    # Restore the monkey patching
    ContractAgency.get_agent = get_agent
    ContractAgency.get_agent_by_contract_name = get_agent_by_name


@pytest.fixture(scope="module")
def coordinator_agent(mock_contract_agency):
    coordinator_agent = mock_contract_agency.get_agent(
        CoordinatorAgent, registry=None, provider_uri=None  # parameters don't matter
    )
    return coordinator_agent


@pytest.fixture(scope="module", autouse=True)
def mock_condition_provider_configuration(module_mocker, testerchain):
    module_mocker.patch.object(
        Operator, "_make_condition_provider", return_value=testerchain.provider
    )


@pytest.fixture(scope="module")
def excluded_staker_address_for_duration_greater_than_0(accounts):
    yield accounts.staking_provider_account(0)


@pytest.fixture(scope="module", autouse=True)
def mock_sample_reservoir(
    accounts,
    mock_contract_agency,
    excluded_staker_address_for_duration_greater_than_0,
):
    def mock_reservoir(
        without: Optional[Iterable[ChecksumAddress]] = None,
        duration: int = 0,
        *args,
        **kwargs
    ):
        addresses = dict()
        for address in accounts.staking_providers_accounts:
            if address in without:
                continue
            if (
                duration > 0
                and address == excluded_staker_address_for_duration_greater_than_0
            ):
                # skip
                continue
            addresses[address] = 1
        return StakingProvidersReservoir(addresses)

    mock_agent = mock_contract_agency.get_agent(TACoChildApplicationAgent)
    mock_agent.get_staking_provider_reservoir = mock_reservoir


@pytest.fixture(scope="module", autouse=True)
def mock_get_all_active_staking_providers(
    accounts,
    mock_contract_agency,
    excluded_staker_address_for_duration_greater_than_0,
):
    def get_all_active_staking_providers(duration):
        addresses = dict()
        for address in accounts.staking_providers_accounts:
            if (
                duration > 0
                and address == excluded_staker_address_for_duration_greater_than_0
            ):
                # skip
                continue
            addresses[address] = 1
        return len(addresses), addresses

    mock_agent = mock_contract_agency.get_agent(TACoChildApplicationAgent)
    mock_agent.get_all_active_staking_providers = get_all_active_staking_providers


@pytest.fixture(scope="module", autouse=True)
def mock_substantiate_stamp(module_mocker, monkeymodule):
    fake_signature = b"\xb1W5?\x9b\xbaix>'\xfe`\x1b\x9f\xeb*9l\xc0\xa7\xb9V\x9a\x83\x84\x04\x97\x0c\xad\x99\x86\x81W\x93l\xc3\xbde\x03\xcd\"Y\xce\xcb\xf7\x02z\xf6\x9c\xac\x84\x05R\x9a\x9f\x97\xf7\xa02\xb2\xda\xa1Gv\x01"
    module_mocker.patch.object(Ursula, "_substantiate_stamp", autospec=True)
    module_mocker.patch.object(Ursula, "operator_signature", fake_signature)
    module_mocker.patch.object(Teacher, "validate_operator")


@pytest.fixture(scope="module")
def mock_signer(get_random_checksum_address):
    signer = MagicMock(spec=Web3Signer)
    signer.sign_message.return_value = (os.urandom(32), os.urandom(32))
    signer.accounts = [get_random_checksum_address()]
    return signer


class _MockMiddlewareClient(_TestMiddlewareClient):
    class MockResponse:
        def __init__(self, json_data, status_code):
            self.json_data = json_data
            self.status_code = status_code

        def json(self):
            return self.json_data

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.ursulas_versions = {}

    def get(self, *args, **kwargs):
        if kwargs.get("path") == "status" and kwargs.get("params")["json"]:
            node_address = kwargs.get("node_or_sprout").checksum_address
            version = self.ursulas_versions.get(node_address, "1.1.1")
            return _MockMiddlewareClient.MockResponse({"version": version}, 200)

        real_get = super(_TestMiddlewareClient, self).__getattr__("get")
        return real_get(*args, **kwargs)


class _MockRestMiddleware(MockRestMiddleware):
    """
    Modified middleware to emulate returning status with version.
    """

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.client = _MockMiddlewareClient(eth_endpoint=TEST_ETH_PROVIDER_URI)

    def set_ursulas_versions(self, ursulas_versions: dict):
        self.client.ursulas_versions = dict(ursulas_versions)

    def clean_ursulas_versions(self):
        self.client.ursulas_versions = {}


@pytest.fixture(scope="module")
def mock_rest_middleware():
    return _MockRestMiddleware(eth_endpoint=TEST_ETH_PROVIDER_URI)


@pytest.fixture(scope="module")
@pytest.mark.usefixtures('testerchain', 'agency')
def porter(ursulas, mock_rest_middleware, test_registry):
    porter = Porter(
        domain=TEMPORARY_DOMAIN,
        eth_endpoint=MOCK_ETH_PROVIDER_URI,
        polygon_endpoint=MOCK_ETH_PROVIDER_URI,
        registry=test_registry,
        abort_on_learning_error=True,
        start_learning_now=True,
        known_nodes=ursulas,
        verify_node_bonding=False,
        network_middleware=mock_rest_middleware,
    )
    yield porter
    porter.stop_learning_loop()


@pytest.fixture(scope='module')
def random_treasure_map_data(alice, bob, ursulas):
    label = b'policy label'
    threshold = 2
    shares = threshold + 1
    policy_key, kfrags = alice.generate_kfrags(bob=bob, label=label, threshold=threshold, shares=shares)
    hrac = HRAC(publisher_verifying_key=alice.stamp.as_umbral_pubkey(),
                bob_verifying_key=bob.stamp.as_umbral_pubkey(),
                label=label)

    assigned_kfrags = {
        Address(ursula.canonical_address): (ursula.public_keys(DecryptingPower), vkfrag)
        for ursula, vkfrag in zip(list(ursulas)[:shares], kfrags)}

    random_treasure_map = TreasureMap(signer=alice.stamp.as_umbral_signer(),
                                      hrac=hrac,
                                      policy_encrypting_key=policy_key,
                                      assigned_kfrags=assigned_kfrags,
                                      threshold=threshold)

    bob_key = bob.public_keys(DecryptingPower)
    enc_treasure_map = random_treasure_map.encrypt(signer=alice.stamp.as_umbral_signer(),
                                                   recipient_key=bob_key)

    yield bob_key, enc_treasure_map


@pytest.fixture(scope='module')
def porter_web_controller(porter, monkeymodule):
    def _setup_prometheus(_porter, app):
        _porter.controller.metrics = PrometheusMetrics(app)
        _porter.controller.metrics.registry = prometheus_client.CollectorRegistry(
            auto_describe=True
        )

    Porter._setup_prometheus = _setup_prometheus
    web_controller = porter.make_web_controller(crash_on_error=False)
    yield web_controller.test_client()


@pytest.fixture(scope="module")
def dkg_setup(
    get_random_checksum_address, ursulas, coordinator_agent
) -> Tuple[int, DkgPublicKey, List[Ursula], int]:
    r_id = 0
    num_shares = 8
    threshold = 5
    cohort = ursulas[:num_shares]

    # configure validator cohort
    validators = []
    for ursula in cohort:
        validators.append(
            Validator(
                address=ursula.checksum_address,
                public_key=ursula.public_keys(RitualisticPower),
            )
        )

    validators.sort(key=lambda x: x.address)  # must be sorted
    cohort.sort(key=lambda x: x.checksum_address)  # sort to match

    # Go through ritual and set up Ursulas
    transcripts = []
    for i, validator in enumerate(validators):
        transcript = dkg.generate_transcript(
            ritual_id=r_id,
            me=validator,
            shares=num_shares,
            threshold=threshold,
            nodes=validators,
        )
        transcripts.append(transcript)

    aggregated_transcript, public_key = dkg.aggregate_transcripts(
        ritual_id=r_id,
        me=validators[0],
        shares=num_shares,
        threshold=threshold,
        transcripts=list(zip(validators, transcripts)),
    )

    now = maya.now()
    ritual = Coordinator.Ritual(
        id=r_id,
        initiator=get_random_checksum_address(),
        authority=get_random_checksum_address(),
        access_controller=get_random_checksum_address(),
        dkg_size=num_shares,
        init_timestamp=now.epoch,
        end_timestamp=now.add(days=1).epoch,
        threshold=threshold,
        total_transcripts=num_shares,
        total_aggregations=num_shares,
        public_key=Ferveo.G1Point.from_dkg_public_key(public_key),
        aggregation_mismatch=False,
        aggregated_transcript=bytes(aggregated_transcript),
        participants=[
            Coordinator.Participant(
                provider=ursula.checksum_address,
                aggregated=True,
                transcript=bytes(transcripts[i]),
                decryption_request_static_key=ursula.threshold_request_power.get_pubkey_from_ritual_id(
                    r_id
                ),
            )
            for i, ursula in enumerate(cohort)
        ],
    )

    for ursula in cohort:
        ursula.dkg_storage.store_validators(r_id, validators)
        ursula.dkg_storage.store_active_ritual(ritual)

    # Configure CoordinatorAgent
    coordinator_agent.__rituals.return_value = ritual
    coordinator_agent.get_ritual_status.return_value = Coordinator.RitualStatus.ACTIVE
    coordinator_agent.is_ritual_active.return_value = True
    coordinator_agent.is_encryption_authorized.return_value = True
    cohort_checksum_addresses = [ursula.checksum_address for ursula in cohort]
    coordinator_agent.is_participant = (
        lambda ritual_id, provider: ritual_id == r_id
        and provider in cohort_checksum_addresses
    )

    def mock_get_provider_public_key(provider, ritual_id):
        for ursula in ursulas:
            if ursula.checksum_address == provider:
                return ursula.public_keys(RitualisticPower)

    coordinator_agent.get_provider_public_key = mock_get_provider_public_key

    return r_id, public_key, cohort, threshold


PLAINTEXT = "peace at dawn"
CONDITIONS = {
    "version": ConditionLingo.VERSION,
    "condition": {
        "conditionType": "time",
        "returnValueTest": {"value": 0, "comparator": ">"},
        "method": "blocktime",
        "chain": TESTERCHAIN_CHAIN_ID,
    },
}


@pytest.mark.usefixtures("mock_rpc_condition")
@pytest.fixture(scope="module")
def dkg_encrypted_data(dkg_setup, mock_signer) -> Tuple[ThresholdMessageKit, bytes]:
    _, public_key, _, _ = dkg_setup
    enrico = Enrico(encrypting_key=public_key, signer=mock_signer)
    threshold_message_kit = enrico.encrypt_for_dkg(
        plaintext=PLAINTEXT.encode(), conditions=CONDITIONS
    )

    return threshold_message_kit, PLAINTEXT.encode()
