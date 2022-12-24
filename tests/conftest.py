import os

import pytest
from click.testing import CliRunner
from eth_utils import to_checksum_address
from nucypher.config.constants import TEMPORARY_DOMAIN
from nucypher.crypto.powers import DecryptingPower
from nucypher.network.nodes import Learner
from nucypher.utilities.logging import GlobalLoggerSettings
from nucypher_core import Address, HRAC, TreasureMap

from porter.emitters import WebEmitter
from porter.main import Porter
from tests.constants import TEST_ETH_PROVIDER_URI

# Crash on server error by default
WebEmitter._crash_on_error_default = True
Learner._DEBUG_MODE = False

pytest_plugins = [
    'pytest-nucypher',  # Includes external fixtures module from nucypher
]

def pytest_addoption(parser):
    parser.addoption("--run-nightly",
                     action="store_true",
                     default=False,
                     help="run tests even if they are marked as nightly")


def pytest_configure(config):
    message = "{0}: mark test as {0} to run (skipped by default, use '{1}' to include these tests)"
    config.addinivalue_line("markers", message.format("nightly", "--run-nightly"))


def pytest_collection_modifyitems(config, items):

    #
    # Handle slow tests marker
    #

    option_markers = {
        "--run-nightly": "nightly"
    }

    for option, marker in option_markers.items():
        option_is_set = config.getoption(option)
        if option_is_set:
            continue

        skip_reason = pytest.mark.skip(reason=f"need {option} option to run tests marked with '@pytest.mark.{marker}'")
        for item in items:
            if marker in item.keywords:
                item.add_marker(skip_reason)

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
@pytest.mark.usefixtures('testerchain', 'agency')
def porter(ursulas, mock_rest_middleware):
    porter = Porter(domain=TEMPORARY_DOMAIN,
                    eth_provider_uri=TEST_ETH_PROVIDER_URI,
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
