import os
import sys

import pytest

# Ensure project root and tests directory are on sys.path for test imports.
TESTS_DIR = os.path.abspath(os.path.dirname(__file__))
PROJECT_ROOT = os.path.abspath(os.path.join(TESTS_DIR, os.pardir))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)
if TESTS_DIR not in sys.path:
    sys.path.insert(0, TESTS_DIR)

from helpers import TEST_PROXY_SECRET, reload_app  # noqa: E402


@pytest.fixture
def temp_state_file(tmp_path):
    """Return a path for an isolated temporary state.json file."""
    return str(tmp_path / "state.json")


@pytest.fixture(autouse=True)
def required_proxy_secret(monkeypatch):
    """Provide a default PROXY_SHARED_SECRET for every test."""
    monkeypatch.setenv("PROXY_SHARED_SECRET", TEST_PROXY_SECRET)


@pytest.fixture
def app_module(monkeypatch, temp_state_file):
    """Reload app with clean isolated defaults and empty runtime state."""
    app = reload_app(
        monkeypatch,
        temp_state_file,
        resource_ids="5",
        proxy_shared_secret=TEST_PROXY_SECRET,
    )
    with app.state_lock:
        app.state.clear()
    with app.state_lock:
        app.rules_cache.clear()
    with app._api_rate_limit_lock:
        app._api_rate_limit.clear()
    return app
