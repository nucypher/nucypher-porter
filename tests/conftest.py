import os

import pytest
from click.testing import CliRunner
from eth_utils import to_checksum_address

from nucypher.config.constants import TEMPORARY_DOMAIN
from porter.main import Porter
from tests.constants import TEST_ETH_PROVIDER_URI
from tests.utils.middleware import MockRestMiddleware


pytest_plugins = [
    'tests.fixtures',  # Includes external fixtures module
]


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
def federated_porter(federated_ursulas):
    porter = Porter(domain=TEMPORARY_DOMAIN,
                    abort_on_learning_error=True,
                    start_learning_now=True,
                    known_nodes=federated_ursulas,
                    verify_node_bonding=False,
                    federated_only=True,
                    execution_timeout=2,
                    network_middleware=MockRestMiddleware())
    yield porter
    porter.stop_learning_loop()


@pytest.fixture(scope="module")
def blockchain_porter(blockchain_ursulas, testerchain, test_registry):
    porter = Porter(domain=TEMPORARY_DOMAIN,
                    abort_on_learning_error=True,
                    start_learning_now=True,
                    known_nodes=blockchain_ursulas,
                    eth_provider_uri=TEST_ETH_PROVIDER_URI,
                    registry=test_registry,
                    execution_timeout=2,
                    network_middleware=MockRestMiddleware())
    yield porter
    porter.stop_learning_loop()

