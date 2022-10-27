import pytest


@pytest.fixture(scope='module')
def blockchain_porter_web_controller(blockchain_porter):
    web_controller = blockchain_porter.make_web_controller(crash_on_error=False)
    yield web_controller.test_client()


@pytest.fixture(scope='module')
def blockchain_porter_basic_auth_web_controller(blockchain_porter, basic_auth_file):
    web_controller = blockchain_porter.make_web_controller(crash_on_error=False, htpasswd_filepath=basic_auth_file)
    yield web_controller.test_client()
