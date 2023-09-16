import pytest
from nucypher.characters.lawful import Ursula
from nucypher.config.constants import TEMPORARY_DOMAIN

from porter.cli.literature import PORTER_CORS_ALLOWED_ORIGINS, PORTER_RUN_MESSAGE
from porter.cli.main import porter_cli
from porter.main import Porter
from tests.constants import TEST_ETH_PROVIDER_URI
from tests.utils.ursula import select_test_port


@pytest.fixture(scope="function")
def teacher_uri(mocker, ursulas, test_registry_source_manager):
    teacher = list(ursulas)[0]
    teacher_uri = teacher.seed_node_metadata(as_teacher_uri=True)
    mocker.patch.object(Ursula, 'from_teacher_uri', return_value=teacher)
    yield teacher_uri


def test_porter_cli_run_simple(click_runner, teacher_uri, test_registry_source_manager):
    porter_run_command = ('run',
                          '--dry-run',
                          '--network', TEMPORARY_DOMAIN,
                          '--eth-provider', TEST_ETH_PROVIDER_URI,
                          '--teacher', teacher_uri)
    result = click_runner.invoke(porter_cli, porter_run_command, catch_exceptions=False)
    assert result.exit_code == 0, result.output
    output = result.output
    assert f"Network: {TEMPORARY_DOMAIN}" in output
    assert PORTER_RUN_MESSAGE.format(http_port=Porter.DEFAULT_PORT) in output

    # Non-default port
    non_default_port = select_test_port()
    porter_run_command = ('run',
                          '--dry-run',
                          '--network', TEMPORARY_DOMAIN,
                          '--eth-provider', TEST_ETH_PROVIDER_URI,
                          '--http-port', non_default_port,
                          '--teacher', teacher_uri)
    result = click_runner.invoke(porter_cli, porter_run_command, catch_exceptions=False)
    assert result.exit_code == 0, result.output
    output = result.output
    assert f"Network: {TEMPORARY_DOMAIN}" in output
    assert PORTER_RUN_MESSAGE.format(http_port=non_default_port) in output


def test_porter_cli_run_eth_provider_must_be_provided(click_runner, teacher_uri, test_registry_source_manager):
    porter_run_command = ('run',
                          '--dry-run',
                          '--network', TEMPORARY_DOMAIN,
                          '--teacher', teacher_uri)
    result = click_runner.invoke(porter_cli, porter_run_command, catch_exceptions=False)
    assert result.exit_code != 0, result.output
    assert f"--eth-provider is required" in result.output


def test_cli_run_with_cors_origin(click_runner,
                                  teacher_uri,
                                  test_registry_source_manager):
    allow_origins = ".*\.example\.com,.*\.otherexample\.org"

    porter_run_command = ('run',
                          '--dry-run',
                          '--network', TEMPORARY_DOMAIN,
                          '--eth-provider', TEST_ETH_PROVIDER_URI,
                          '--teacher', teacher_uri,
                          '--allow-origins', allow_origins)
    result = click_runner.invoke(porter_cli, porter_run_command, catch_exceptions=False)
    assert result.exit_code == 0, result.output
    assert PORTER_RUN_MESSAGE.format(http_port=Porter.DEFAULT_PORT) in result.output
    assert PORTER_CORS_ALLOWED_ORIGINS.format(allow_origins=allow_origins.split(",")) in result.output


def test_cli_run_with_empty_string_cors_origin(click_runner,
                                               teacher_uri,
                                               test_registry_source_manager):
    empty_string_allow_origins = ""

    porter_run_command = ('run',
                          '--dry-run',
                          '--network', TEMPORARY_DOMAIN,
                          '--eth-provider', TEST_ETH_PROVIDER_URI,
                          '--teacher', teacher_uri,
                          '--allow-origins', empty_string_allow_origins)
    result = click_runner.invoke(porter_cli, porter_run_command, catch_exceptions=False)
    assert result.exit_code == 0, result.output
    assert PORTER_RUN_MESSAGE.format(http_port=Porter.DEFAULT_PORT) in result.output
    # empty string translates to CORS not being enabled - empty origin string provides wild card comparison
    # with just header
    assert PORTER_CORS_ALLOWED_ORIGINS.format(allow_origins='') not in result.output
