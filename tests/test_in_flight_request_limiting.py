"""
Tests for WebController in-flight request limiting functionality.

This test module validates the semaphore-based request limiting implemented
in the WebController's before_request and teardown_request hooks.
"""

import json
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from unittest.mock import MagicMock

import pytest

from porter.controllers import WebController
from porter.interfaces import PorterInterface


@pytest.fixture(scope="function")
def web_controller():
    """Create a WebController with uncapped paths."""
    controller = WebController(
        interface=MagicMock(spec=PorterInterface),
        app_name="test-porter",
        crash_on_error=False,
        in_flight_uncapped_paths={"/uncapped_endpoint"},
    )
    controller.make_control_transport()

    @controller._transport.route("/uncapped_endpoint", methods=["POST"])
    def uncapped_endpoint():
        time.sleep(0.05)
        return json.dumps({"result": "uncapped_success"}), 200

    @controller._transport.route("/capped_endpoint", methods=["POST"])
    def capped_endpoint():
        time.sleep(0.05)
        return json.dumps({"result": "capped_success"}), 200

    yield controller


def test_semaphore_acquire_and_release_directly(web_controller):
    """Test semaphore acquire and release mechanism directly."""
    web_controller.make_control_transport()
    try:
        # Test that we can acquire up to the limit
        for i in range(web_controller._DEPLOYER_MAX_IN_FLIGHT_REQUESTS):
            assert web_controller._inflight_sem.acquire(timeout=0.1)

        # This acquire should fail (timeout)
        assert not web_controller._inflight_sem.acquire(timeout=0.05)

        # Release one slot
        web_controller._inflight_sem.release()

        # Now we should be able to acquire again
        assert web_controller._inflight_sem.acquire(timeout=0.1)
    finally:
        # Clean up
        current_value = web_controller._inflight_sem._value
        web_controller._inflight_sem.release(
            web_controller._DEPLOYER_MAX_IN_FLIGHT_REQUESTS - current_value
        )


def test_single_request_acquires_and_releases_slot(web_controller):
    """Test that a single request properly acquires and releases a semaphore slot."""
    # initial values should be at max
    assert (
        web_controller._inflight_sem._value
        == WebController._DEPLOYER_MAX_IN_FLIGHT_REQUESTS
    )
    test_client = web_controller.test_client()

    response = test_client.post("/capped_endpoint")
    assert response.status_code == 200
    data = json.loads(response.data)
    assert data["result"] == "capped_success"

    # after request completes, semaphore should be fully released again
    assert (
        web_controller._inflight_sem._value
        == WebController._DEPLOYER_MAX_IN_FLIGHT_REQUESTS
    )


def test_semaphore_release_on_request_completion(web_controller):
    """Test that semaphore slots are properly released after request completion."""
    # Make multiple sequential requests
    assert (
        web_controller._inflight_sem._value
        == WebController._DEPLOYER_MAX_IN_FLIGHT_REQUESTS
    )
    test_client = web_controller.test_client()

    for i in range(
        WebController._DEPLOYER_MAX_IN_FLIGHT_REQUESTS * 2
    ):  # More than the limit, but sequential
        response = test_client.post("/capped_endpoint")
        assert response.status_code == 200, f"Request {i} failed"
        data = json.loads(response.data)
        assert data["result"] == "capped_success"

    # After all requests, semaphore should be fully released
    assert (
        web_controller._inflight_sem._value
        == WebController._DEPLOYER_MAX_IN_FLIGHT_REQUESTS
    )


def test_concurrent_requests_within_limit(web_controller):
    """Test that concurrent requests within the limit all succeed."""
    # Sequential requests should all work fine
    assert (
        web_controller._inflight_sem._value
        == WebController._DEPLOYER_MAX_IN_FLIGHT_REQUESTS
    )
    test_client = web_controller.test_client()

    n_threads = WebController._DEPLOYER_MAX_IN_FLIGHT_REQUESTS
    futures = []
    with ThreadPoolExecutor(max_workers=n_threads) as executor:
        for i in range(n_threads):
            future = executor.submit(test_client.post, "/capped_endpoint")
            futures.append(future)

        for future in as_completed(futures):
            response = future.result()
            assert response.status_code == 200
            data = json.loads(response.data)
            assert data["result"] == "capped_success"

    assert (
        web_controller._inflight_sem._value
        == WebController._DEPLOYER_MAX_IN_FLIGHT_REQUESTS
    )


def test_uncapped_path_bypasses_semaphore(web_controller):
    """Test that uncapped paths don't acquire the semaphore."""
    test_client = web_controller.test_client()
    try:
        # Even if we hold all semaphore slots, uncapped path should work
        for _ in range(web_controller._DEPLOYER_MAX_IN_FLIGHT_REQUESTS):
            web_controller._inflight_sem.acquire()

        assert web_controller._inflight_sem._value == 0

        # Make many requests to uncapped endpoint - all should succeed
        for _ in range(5):
            response = test_client.post("/uncapped_endpoint")
            # Semaphore should not be affected
            assert web_controller._inflight_sem._value == 0

            assert response.status_code == 200
            data = json.loads(response.data)
            assert data["result"] == "uncapped_success"
    finally:
        # Clean up
        web_controller._inflight_sem.release(
            web_controller._DEPLOYER_MAX_IN_FLIGHT_REQUESTS
        )


def test_capped_endpoint_too_many_concurrent_requests_returns_429(web_controller):
    """Test that exceeding the in-flight limit returns a 429 status code."""
    test_client = web_controller.test_client()
    try:
        # Even if we hold all semaphore slots, uncapped path should work
        for _ in range(web_controller._DEPLOYER_MAX_IN_FLIGHT_REQUESTS):
            web_controller._inflight_sem.acquire()

        assert web_controller._inflight_sem._value == 0

        # Make many requests to uncapped endpoint - all should succeed
        response = test_client.post("/capped_endpoint")

        # Semaphore should not be affected
        assert web_controller._inflight_sem._value == 0

        assert response.status_code == 429
        data = json.loads(response.data)
        assert data["error"] == "too_many_requests"
        assert data["message"] == "Too many in-flight requests."
        assert response.headers.get("Retry-After") == "3"
    finally:
        # Clean up
        for _ in range(web_controller._DEPLOYER_MAX_IN_FLIGHT_REQUESTS):
            web_controller._inflight_sem.release()
