import pytest


@pytest.fixture(scope='module')
def federated_porter_web_controller(federated_porter):
    web_controller = federated_porter.make_web_controller(crash_on_error=False)
    yield web_controller.test_client()


@pytest.fixture(scope='module')
def federated_porter_basic_auth_web_controller(federated_porter, basic_auth_file):
    web_controller = federated_porter.make_web_controller(crash_on_error=False, htpasswd_filepath=basic_auth_file)
    yield web_controller.test_client()
