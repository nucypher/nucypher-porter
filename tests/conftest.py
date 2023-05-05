import os
from typing import Optional, Iterable

import pytest
from click.testing import CliRunner
from eth_typing import ChecksumAddress
from eth_utils import to_checksum_address
from nucypher.blockchain.economics import EconomicsFactory, Economics
from nucypher.blockchain.eth.actors import Operator
from nucypher.blockchain.eth.agents import ContractAgency, PREApplicationAgent, \
    StakingProvidersReservoir
from nucypher.blockchain.eth.interfaces import BlockchainInterfaceFactory
from nucypher.blockchain.eth.registry import InMemoryContractRegistry
from nucypher.characters.lawful import Ursula
from nucypher.config.constants import TEMPORARY_DOMAIN
from nucypher.crypto.powers import DecryptingPower
from nucypher.network.nodes import Learner, Teacher
from nucypher.utilities.logging import GlobalLoggerSettings
from nucypher_core import Address, HRAC, TreasureMap
from tests.constants import MOCK_ETH_PROVIDER_URI
from tests.mock.interfaces import MockBlockchain, mock_registry_source_manager

from porter.emitters import WebEmitter
from porter.main import Porter

# Crash on server error by default
WebEmitter._crash_on_error_default = True
Learner._DEBUG_MODE = False

pytest_plugins = [
    'pytest-nucypher',  # Includes external fixtures module from nucypher
]

def pytest_addhooks(pluginmanager):
    pluginmanager.set_blocked('ape_test')


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


@pytest.fixture(scope='module')
def test_registry():
    return InMemoryContractRegistry()


@pytest.fixture(scope="module", autouse=True)
def staking_providers(testerchain, test_registry, monkeymodule):
    def faked(self, *args, **kwargs):
        return testerchain.stake_providers_accounts[
            testerchain.ursulas_accounts.index(self.transacting_power.account)
        ]

    Operator.get_staking_provider_address = faked
    return testerchain.stake_providers_accounts

@pytest.fixture(scope='module')
def application_economics():
    economics = Economics()
    return economics


@pytest.fixture(scope='module', autouse=True)
def mock_contract_agency(module_mocker, application_economics):

    # Patch
    module_mocker.patch.object(EconomicsFactory, 'get_economics', return_value=application_economics)

    from tests.mock.agents import MockContractAgency

    # Monkeypatch # TODO: Use better tooling for this monkeypatch?
    get_agent = ContractAgency.get_agent
    get_agent_by_name = ContractAgency.get_agent_by_contract_name
    ContractAgency.get_agent = MockContractAgency.get_agent
    ContractAgency.get_agent_by_contract_name = MockContractAgency.get_agent_by_contract_name

    # Test
    yield MockContractAgency()

    # Restore the monkey patching
    ContractAgency.get_agent = get_agent
    ContractAgency.get_agent_by_contract_name = get_agent_by_name


@pytest.fixture(scope="module", autouse=True)
def mock_sample_reservoir(testerchain, mock_contract_agency):
    def mock_reservoir(
        without: Optional[Iterable[ChecksumAddress]] = None, *args, **kwargs
    ):
        addresses = {
            address: 1
            for address in testerchain.stake_providers_accounts
            if address not in without
        }
        return StakingProvidersReservoir(addresses)

    mock_agent = mock_contract_agency.get_agent(PREApplicationAgent)
    mock_agent.get_staking_provider_reservoir = mock_reservoir


@pytest.fixture(scope="module", autouse=True)
def mock_substantiate_stamp(module_mocker, monkeymodule):
    fake_signature = b'\xb1W5?\x9b\xbaix>\'\xfe`\x1b\x9f\xeb*9l\xc0\xa7\xb9V\x9a\x83\x84\x04\x97\x0c\xad\x99\x86\x81W\x93l\xc3\xbde\x03\xcd"Y\xce\xcb\xf7\x02z\xf6\x9c\xac\x84\x05R\x9a\x9f\x97\xf7\xa02\xb2\xda\xa1Gv\x01'
    module_mocker.patch.object(Ursula, "_substantiate_stamp", autospec=True)
    module_mocker.patch.object(Ursula, "operator_signature", fake_signature)
    module_mocker.patch.object(Teacher, "validate_operator")


@pytest.fixture(scope='module')
def test_registry_source_manager(test_registry):
    with mock_registry_source_manager(test_registry=test_registry):
        yield


@pytest.fixture(scope="module")
@pytest.mark.usefixtures('testerchain', 'agency')
def porter(ursulas, mock_rest_middleware, test_registry):
    porter = Porter(domain=TEMPORARY_DOMAIN,
                    eth_provider_uri=MOCK_ETH_PROVIDER_URI,
                    registry=test_registry,
                    abort_on_learning_error=True,
                    start_learning_now=True,
                    known_nodes=ursulas,
                    verify_node_bonding=False,
                    execution_timeout=2,
                    network_middleware=mock_rest_middleware)
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
def porter_web_controller(porter):
    web_controller = porter.make_web_controller(crash_on_error=False)
    yield web_controller.test_client()
