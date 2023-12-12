import pytest

from porter.main import Porter


@pytest.mark.parametrize(
    "timeout_scenarios",
    [
        (None, 10, 10),
        (1, 10, 1),
        (5, 10, 5),
        (9, 10, 9),
        (10, 10, 10),
        (11, 10, 10),
        (20, 10, 10),
        (25, 10, 10),
        (
            Porter.MAX_GET_URSULAS_TIMEOUT - 1,
            Porter.MAX_GET_URSULAS_TIMEOUT,
            Porter.MAX_GET_URSULAS_TIMEOUT - 1,
        ),
        (
            Porter.MAX_GET_URSULAS_TIMEOUT + 1,
            Porter.MAX_GET_URSULAS_TIMEOUT,
            Porter.MAX_GET_URSULAS_TIMEOUT,
        ),
        (
            Porter.MAX_DECRYPTION_TIMEOUT / 2,
            Porter.MAX_DECRYPTION_TIMEOUT,
            Porter.MAX_DECRYPTION_TIMEOUT / 2,
        ),
        (
            Porter.MAX_DECRYPTION_TIMEOUT * 2,
            Porter.MAX_DECRYPTION_TIMEOUT,
            Porter.MAX_DECRYPTION_TIMEOUT,
        ),
    ],
)
def test_porter_configure_timeout_defined_results(porter, timeout_scenarios):
    provided_timeout, max_timeout, expected_timeout = timeout_scenarios
    resultant_timeout = porter._configure_timeout(
        operation="test", timeout=provided_timeout, max_timeout=max_timeout
    )
    assert resultant_timeout == expected_timeout
