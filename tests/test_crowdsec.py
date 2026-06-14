"""
Unit tests for crowdsec_connector.py.

All tests use monkeypatch to avoid real subprocess calls. No live CrowdSec
instance or network access is required to run this suite.

Note: _build_cscli_cmd() and _parse_crowdsec_entries_from_json() are already
covered in tests/test_app.py and are not duplicated here.
"""

import subprocess
import time as _time

import pytest


@pytest.fixture(autouse=True)
def reset_crowdsec_module_state():
    """Reset mutable module-level globals before and after each test.

    crowdsec_connector carries two mutable globals — _crowdsec_allowlist_ready
    and _crowdsec_cache — that are mutated in place by the functions under test.
    Resetting them here keeps tests fully isolated without requiring a module
    reload between every case.
    """
    import crowdsec_connector

    crowdsec_connector._crowdsec_allowlist_ready = False
    with crowdsec_connector._cache_lock:
        crowdsec_connector._crowdsec_cache["ts"] = 0.0
        crowdsec_connector._crowdsec_cache["ip_set"] = set()
    yield
    crowdsec_connector._crowdsec_allowlist_ready = False
    with crowdsec_connector._cache_lock:
        crowdsec_connector._crowdsec_cache["ts"] = 0.0
        crowdsec_connector._crowdsec_cache["ip_set"] = set()


# ---------------------------------------------------------------------------
# run_cscli — subprocess wrapper
# ---------------------------------------------------------------------------


def test_run_cscli_success(monkeypatch):
    """Successful run returns (0, stripped-stdout, "")."""
    import crowdsec_connector

    class FakeResult:
        returncode = 0
        stdout = "  output text  "
        stderr = ""

    monkeypatch.setattr(subprocess, "run", lambda cmd, **kw: FakeResult())
    rc, out, err = crowdsec_connector.run_cscli(["allowlist", "list"])
    assert rc == 0
    assert out == "output text"
    assert err == ""


def test_run_cscli_nonzero_return(monkeypatch):
    """Non-zero returncode is returned as-is with stderr."""
    import crowdsec_connector

    class FakeResult:
        returncode = 1
        stdout = ""
        stderr = "something failed"

    monkeypatch.setattr(subprocess, "run", lambda cmd, **kw: FakeResult())
    rc, out, err = crowdsec_connector.run_cscli(["allowlist", "list"])
    assert rc == 1
    assert err == "something failed"


def test_run_cscli_file_not_found(monkeypatch):
    """FileNotFoundError (cscli not on PATH) returns (127, "", "cscli not found")."""
    import crowdsec_connector

    monkeypatch.setattr(
        subprocess, "run", lambda cmd, **kw: (_ for _ in ()).throw(FileNotFoundError())
    )
    rc, out, err = crowdsec_connector.run_cscli(["allowlist", "list"])
    assert rc == 127
    assert out == ""
    assert "not found" in err


def test_run_cscli_timeout(monkeypatch):
    """TimeoutExpired returns (1, "", non-empty error string)."""
    import crowdsec_connector

    def raise_timeout(cmd, **kw):
        raise subprocess.TimeoutExpired(cmd, 15)

    monkeypatch.setattr(subprocess, "run", raise_timeout)
    rc, out, err = crowdsec_connector.run_cscli(["allowlist", "list"])
    assert rc == 1
    assert out == ""
    assert err


def test_run_cscli_generic_exception(monkeypatch):
    """Unexpected exception returns (1, "", str(exception))."""
    import crowdsec_connector

    def raise_generic(cmd, **kw):
        raise RuntimeError("unexpected failure")

    monkeypatch.setattr(subprocess, "run", raise_generic)
    rc, out, err = crowdsec_connector.run_cscli(["allowlist", "list"])
    assert rc == 1
    assert "unexpected failure" in err


# ---------------------------------------------------------------------------
# crowdsec_allowlist_exists
# ---------------------------------------------------------------------------


def test_allowlist_exists_found_via_json(monkeypatch):
    """JSON list output containing the name returns True."""
    import crowdsec_connector

    monkeypatch.setattr(
        crowdsec_connector,
        "run_cscli",
        lambda args: (0, '[{"name": "pangolin-ip-rule-manager"}]', ""),
    )
    assert (
        crowdsec_connector.crowdsec_allowlist_exists("pangolin-ip-rule-manager") is True
    )


def test_allowlist_exists_name_not_in_json(monkeypatch):
    """Name absent from JSON list returns False."""
    import crowdsec_connector

    monkeypatch.setattr(
        crowdsec_connector,
        "run_cscli",
        lambda args: (0, '[{"name": "other-list"}]', ""),
    )
    assert (
        crowdsec_connector.crowdsec_allowlist_exists("pangolin-ip-rule-manager")
        is False
    )


def test_allowlist_exists_fallback_text_search(monkeypatch):
    """Falls back to plain-text search when JSON command fails; name in output returns True."""
    import crowdsec_connector

    def fake_run(args):
        if "-o" in args and "json" in args:
            return 1, "", "flag not supported"
        return 0, "pangolin-ip-rule-manager  auto-created", ""

    monkeypatch.setattr(crowdsec_connector, "run_cscli", fake_run)
    assert (
        crowdsec_connector.crowdsec_allowlist_exists("pangolin-ip-rule-manager") is True
    )


def test_allowlist_exists_all_attempts_fail(monkeypatch):
    """All lookup attempts fail — returns False without raising."""
    import crowdsec_connector

    monkeypatch.setattr(crowdsec_connector, "run_cscli", lambda args: (1, "", "error"))
    assert (
        crowdsec_connector.crowdsec_allowlist_exists("pangolin-ip-rule-manager")
        is False
    )


# ---------------------------------------------------------------------------
# crowdsec_create_allowlist
# ---------------------------------------------------------------------------


def test_create_allowlist_success(monkeypatch):
    """Successful cscli create returns True."""
    import crowdsec_connector

    monkeypatch.setattr(crowdsec_connector, "run_cscli", lambda args: (0, "", ""))
    assert crowdsec_connector.crowdsec_create_allowlist("test-list") is True


def test_create_allowlist_failure(monkeypatch):
    """Failed cscli create returns False without raising."""
    import crowdsec_connector

    monkeypatch.setattr(
        crowdsec_connector, "run_cscli", lambda args: (1, "", "permission denied")
    )
    assert crowdsec_connector.crowdsec_create_allowlist("test-list") is False


# ---------------------------------------------------------------------------
# crowdsec_ensure_allowlist
# ---------------------------------------------------------------------------


def test_ensure_allowlist_disabled(monkeypatch):
    """CROWDSEC_ENABLED=False — no subprocess calls, _ready stays False."""
    import crowdsec_connector

    monkeypatch.setattr(crowdsec_connector, "CROWDSEC_ENABLED", False)
    calls = []
    monkeypatch.setattr(
        crowdsec_connector,
        "run_cscli",
        lambda args: calls.append(args) or (0, "", ""),
    )
    crowdsec_connector.crowdsec_ensure_allowlist()
    assert calls == []
    assert not crowdsec_connector._crowdsec_allowlist_ready


def test_ensure_allowlist_idempotent(monkeypatch):
    """_crowdsec_allowlist_ready=True — second call is a complete no-op."""
    import crowdsec_connector

    monkeypatch.setattr(crowdsec_connector, "CROWDSEC_ENABLED", True)
    crowdsec_connector._crowdsec_allowlist_ready = True
    calls = []
    monkeypatch.setattr(
        crowdsec_connector,
        "run_cscli",
        lambda args: calls.append(args) or (0, "", ""),
    )
    crowdsec_connector.crowdsec_ensure_allowlist()
    assert calls == []


def test_ensure_allowlist_already_exists(monkeypatch):
    """Allowlist exists — no create call, _ready set True."""
    import crowdsec_connector

    monkeypatch.setattr(crowdsec_connector, "CROWDSEC_ENABLED", True)
    monkeypatch.setattr(crowdsec_connector, "CROWDSEC_ALLOWLIST_NAME", "test-list")
    monkeypatch.setattr(
        crowdsec_connector, "crowdsec_allowlist_exists", lambda name: True
    )
    created = []
    monkeypatch.setattr(
        crowdsec_connector,
        "crowdsec_create_allowlist",
        lambda name: created.append(name) or True,
    )
    crowdsec_connector.crowdsec_ensure_allowlist()
    assert created == []
    assert crowdsec_connector._crowdsec_allowlist_ready


def test_ensure_allowlist_creates_when_missing(monkeypatch):
    """Allowlist missing — create called with configured name, _ready set True."""
    import crowdsec_connector

    monkeypatch.setattr(crowdsec_connector, "CROWDSEC_ENABLED", True)
    monkeypatch.setattr(crowdsec_connector, "CROWDSEC_ALLOWLIST_NAME", "test-list")
    monkeypatch.setattr(
        crowdsec_connector, "crowdsec_allowlist_exists", lambda name: False
    )
    created = []
    monkeypatch.setattr(
        crowdsec_connector,
        "crowdsec_create_allowlist",
        lambda name: created.append(name) or True,
    )
    crowdsec_connector.crowdsec_ensure_allowlist()
    assert created == ["test-list"]
    assert crowdsec_connector._crowdsec_allowlist_ready


def test_ensure_allowlist_create_fails_warns_continues(monkeypatch, capsys):
    """Create fails — WARNING printed, _ready still set True (warn and continue)."""
    import crowdsec_connector

    monkeypatch.setattr(crowdsec_connector, "CROWDSEC_ENABLED", True)
    monkeypatch.setattr(crowdsec_connector, "CROWDSEC_ALLOWLIST_NAME", "test-list")
    monkeypatch.setattr(
        crowdsec_connector, "crowdsec_allowlist_exists", lambda name: False
    )
    monkeypatch.setattr(
        crowdsec_connector, "crowdsec_create_allowlist", lambda name: False
    )
    crowdsec_connector.crowdsec_ensure_allowlist()
    assert crowdsec_connector._crowdsec_allowlist_ready
    out = capsys.readouterr().out
    assert "WARNING" in out or "warning" in out.lower()


# ---------------------------------------------------------------------------
# _crowdsec_refresh_allowlist_ip_set
# ---------------------------------------------------------------------------


def test_refresh_disabled_returns_empty(monkeypatch):
    """CROWDSEC_ENABLED=False — returns empty set without calling run_cscli."""
    import crowdsec_connector

    monkeypatch.setattr(crowdsec_connector, "CROWDSEC_ENABLED", False)
    calls = []
    monkeypatch.setattr(
        crowdsec_connector,
        "run_cscli",
        lambda args: calls.append(args) or (0, "", ""),
    )
    result = crowdsec_connector._crowdsec_refresh_allowlist_ip_set()
    assert result == set()
    assert calls == []


def test_refresh_parses_and_updates_cache(monkeypatch):
    """Successful refresh stores parsed IPs in the cache and returns them."""
    import crowdsec_connector

    monkeypatch.setattr(crowdsec_connector, "CROWDSEC_ENABLED", True)
    monkeypatch.setattr(crowdsec_connector, "CROWDSEC_ALLOWLIST_NAME", "test-list")
    monkeypatch.setattr(
        crowdsec_connector,
        "run_cscli",
        lambda args: (0, '[{"ip": "1.2.3.4"}, {"ip": "5.6.7.8"}]', ""),
    )
    result = crowdsec_connector._crowdsec_refresh_allowlist_ip_set()
    assert result == {"1.2.3.4", "5.6.7.8"}
    with crowdsec_connector._cache_lock:
        assert crowdsec_connector._crowdsec_cache["ip_set"] == {"1.2.3.4", "5.6.7.8"}
        assert crowdsec_connector._crowdsec_cache["ts"] > 0


def test_refresh_cscli_fails_caches_empty_set(monkeypatch):
    """Failed cscli inspect — cache is stamped with empty set, returns empty set."""
    import crowdsec_connector

    monkeypatch.setattr(crowdsec_connector, "CROWDSEC_ENABLED", True)
    monkeypatch.setattr(crowdsec_connector, "CROWDSEC_ALLOWLIST_NAME", "test-list")
    monkeypatch.setattr(crowdsec_connector, "run_cscli", lambda args: (1, "", "error"))
    result = crowdsec_connector._crowdsec_refresh_allowlist_ip_set()
    assert result == set()
    with crowdsec_connector._cache_lock:
        assert crowdsec_connector._crowdsec_cache["ts"] > 0


# ---------------------------------------------------------------------------
# _crowdsec_ip_known_or_refresh
# ---------------------------------------------------------------------------


def test_ip_known_in_cache_no_refresh(monkeypatch):
    """IP found in cache — returns True without triggering a refresh."""
    import crowdsec_connector

    monkeypatch.setattr(
        crowdsec_connector, "_get_crowdsec_ip_set_cached", lambda: {"1.2.3.4"}
    )
    refresh_calls = []
    monkeypatch.setattr(
        crowdsec_connector,
        "_crowdsec_refresh_allowlist_ip_set",
        lambda: refresh_calls.append(1) or set(),
    )
    assert crowdsec_connector._crowdsec_ip_known_or_refresh("1.2.3.4") is True
    assert refresh_calls == []


def test_ip_not_in_cache_refresh_finds_it(monkeypatch):
    """IP absent from cache — refresh called, IP found in result."""
    import crowdsec_connector

    monkeypatch.setattr(
        crowdsec_connector, "_get_crowdsec_ip_set_cached", lambda: set()
    )
    monkeypatch.setattr(
        crowdsec_connector, "_crowdsec_refresh_allowlist_ip_set", lambda: {"1.2.3.4"}
    )
    assert crowdsec_connector._crowdsec_ip_known_or_refresh("1.2.3.4") is True


def test_ip_not_in_cache_refresh_also_empty(monkeypatch):
    """IP absent from cache and absent from refresh — returns False."""
    import crowdsec_connector

    monkeypatch.setattr(
        crowdsec_connector, "_get_crowdsec_ip_set_cached", lambda: set()
    )
    monkeypatch.setattr(
        crowdsec_connector, "_crowdsec_refresh_allowlist_ip_set", lambda: set()
    )
    assert crowdsec_connector._crowdsec_ip_known_or_refresh("1.2.3.4") is False


# ---------------------------------------------------------------------------
# crowdsec_add_ip
# ---------------------------------------------------------------------------


def test_add_ip_disabled(monkeypatch):
    """CROWDSEC_ENABLED=False — no subprocess calls."""
    import crowdsec_connector

    monkeypatch.setattr(crowdsec_connector, "CROWDSEC_ENABLED", False)
    calls = []
    monkeypatch.setattr(
        crowdsec_connector,
        "run_cscli",
        lambda args: calls.append(args) or (0, "", ""),
    )
    crowdsec_connector.crowdsec_add_ip("1.2.3.4")
    assert calls == []


def test_add_ip_already_present_skips_cscli(monkeypatch):
    """IP already known (cache/refresh) — cscli add is not called."""
    import crowdsec_connector

    monkeypatch.setattr(crowdsec_connector, "CROWDSEC_ENABLED", True)
    monkeypatch.setattr(crowdsec_connector, "crowdsec_ensure_allowlist", lambda: None)
    monkeypatch.setattr(
        crowdsec_connector, "_crowdsec_ip_known_or_refresh", lambda ip: True
    )
    calls = []
    monkeypatch.setattr(
        crowdsec_connector,
        "run_cscli",
        lambda args: calls.append(args) or (0, "", ""),
    )
    crowdsec_connector.crowdsec_add_ip("1.2.3.4")
    assert not any("add" in " ".join(c) for c in calls)


def test_add_ip_success_stores_in_cache(monkeypatch):
    """Successful add — cscli called with 'add' args, IP stored in cache."""
    import crowdsec_connector

    monkeypatch.setattr(crowdsec_connector, "CROWDSEC_ENABLED", True)
    monkeypatch.setattr(crowdsec_connector, "CROWDSEC_ALLOWLIST_NAME", "test-list")
    monkeypatch.setattr(crowdsec_connector, "crowdsec_ensure_allowlist", lambda: None)
    monkeypatch.setattr(
        crowdsec_connector, "_crowdsec_ip_known_or_refresh", lambda ip: False
    )
    calls = []
    monkeypatch.setattr(
        crowdsec_connector,
        "run_cscli",
        lambda args: calls.append(args) or (0, "", ""),
    )
    crowdsec_connector.crowdsec_add_ip("1.2.3.4")
    assert any("add" in " ".join(c) for c in calls)
    with crowdsec_connector._cache_lock:
        assert "1.2.3.4" in crowdsec_connector._crowdsec_cache["ip_set"]


def test_add_ip_retry_on_transient_failure(monkeypatch):
    """First attempt fails, second succeeds — no exception, 2 attempts made."""
    import crowdsec_connector

    monkeypatch.setattr(crowdsec_connector, "CROWDSEC_ENABLED", True)
    monkeypatch.setattr(crowdsec_connector, "CROWDSEC_ALLOWLIST_NAME", "test-list")
    monkeypatch.setattr(crowdsec_connector, "crowdsec_ensure_allowlist", lambda: None)
    monkeypatch.setattr(
        crowdsec_connector, "_crowdsec_ip_known_or_refresh", lambda ip: False
    )
    monkeypatch.setattr(_time, "sleep", lambda s: None)
    attempts = {"n": 0}

    def fake_run(args):
        attempts["n"] += 1
        return (1, "", "transient") if attempts["n"] < 2 else (0, "", "")

    monkeypatch.setattr(crowdsec_connector, "run_cscli", fake_run)
    crowdsec_connector.crowdsec_add_ip("1.2.3.4")
    assert attempts["n"] == 2


def test_add_ip_all_retries_exhausted_raises(monkeypatch):
    """All 3 add attempts fail and IP absent from refresh — RuntimeError raised."""
    import crowdsec_connector

    monkeypatch.setattr(crowdsec_connector, "CROWDSEC_ENABLED", True)
    monkeypatch.setattr(crowdsec_connector, "CROWDSEC_ALLOWLIST_NAME", "test-list")
    monkeypatch.setattr(crowdsec_connector, "crowdsec_ensure_allowlist", lambda: None)
    monkeypatch.setattr(
        crowdsec_connector, "_crowdsec_ip_known_or_refresh", lambda ip: False
    )
    monkeypatch.setattr(
        crowdsec_connector, "_crowdsec_refresh_allowlist_ip_set", lambda: set()
    )
    monkeypatch.setattr(_time, "sleep", lambda s: None)
    monkeypatch.setattr(crowdsec_connector, "run_cscli", lambda args: (1, "", "error"))
    with pytest.raises(RuntimeError, match="failed to add"):
        crowdsec_connector.crowdsec_add_ip("1.2.3.4")


def test_add_ip_all_retries_fail_but_ip_appears_in_refresh(monkeypatch):
    """All retries fail but IP found in post-failure refresh — no exception (idempotent add)."""
    import crowdsec_connector

    monkeypatch.setattr(crowdsec_connector, "CROWDSEC_ENABLED", True)
    monkeypatch.setattr(crowdsec_connector, "CROWDSEC_ALLOWLIST_NAME", "test-list")
    monkeypatch.setattr(crowdsec_connector, "crowdsec_ensure_allowlist", lambda: None)
    monkeypatch.setattr(
        crowdsec_connector, "_crowdsec_ip_known_or_refresh", lambda ip: False
    )
    monkeypatch.setattr(
        crowdsec_connector,
        "_crowdsec_refresh_allowlist_ip_set",
        lambda: {"1.2.3.4"},
    )
    monkeypatch.setattr(_time, "sleep", lambda s: None)
    monkeypatch.setattr(
        crowdsec_connector, "run_cscli", lambda args: (1, "", "already exists")
    )
    crowdsec_connector.crowdsec_add_ip("1.2.3.4")  # must not raise


# ---------------------------------------------------------------------------
# crowdsec_remove_ip
# ---------------------------------------------------------------------------


def test_remove_ip_disabled(monkeypatch):
    """CROWDSEC_ENABLED=False — no subprocess calls."""
    import crowdsec_connector

    monkeypatch.setattr(crowdsec_connector, "CROWDSEC_ENABLED", False)
    calls = []
    monkeypatch.setattr(
        crowdsec_connector,
        "run_cscli",
        lambda args: calls.append(args) or (0, "", ""),
    )
    crowdsec_connector.crowdsec_remove_ip("1.2.3.4")
    assert calls == []


def test_remove_ip_not_in_cache_or_refresh_skips(monkeypatch):
    """IP absent from cache and refresh — no removal attempted."""
    import crowdsec_connector

    monkeypatch.setattr(crowdsec_connector, "CROWDSEC_ENABLED", True)
    monkeypatch.setattr(
        crowdsec_connector, "_get_crowdsec_ip_set_cached", lambda: set()
    )
    monkeypatch.setattr(
        crowdsec_connector, "_crowdsec_refresh_allowlist_ip_set", lambda: set()
    )
    calls = []
    monkeypatch.setattr(
        crowdsec_connector,
        "run_cscli",
        lambda args: calls.append(args) or (0, "", ""),
    )
    crowdsec_connector.crowdsec_remove_ip("1.2.3.4")
    assert calls == []


def test_remove_ip_present_in_cache_removes_and_updates_cache(monkeypatch):
    """IP found in cache — remove called, IP discarded from cache."""
    import crowdsec_connector

    monkeypatch.setattr(crowdsec_connector, "CROWDSEC_ENABLED", True)
    monkeypatch.setattr(crowdsec_connector, "CROWDSEC_ALLOWLIST_NAME", "test-list")
    monkeypatch.setattr(
        crowdsec_connector, "_get_crowdsec_ip_set_cached", lambda: {"1.2.3.4"}
    )
    calls = []
    monkeypatch.setattr(
        crowdsec_connector,
        "run_cscli",
        lambda args: calls.append(args) or (0, "", ""),
    )
    # Pre-populate the actual cache so the post-removal discard finds something
    with crowdsec_connector._cache_lock:
        crowdsec_connector._crowdsec_cache["ip_set"] = {"1.2.3.4"}
    crowdsec_connector.crowdsec_remove_ip("1.2.3.4")
    assert any("remove" in " ".join(c) for c in calls)
    with crowdsec_connector._cache_lock:
        assert "1.2.3.4" not in crowdsec_connector._crowdsec_cache["ip_set"]


def test_remove_ip_found_only_in_refresh(monkeypatch):
    """IP absent from cache but found in refresh — removal still attempted."""
    import crowdsec_connector

    monkeypatch.setattr(crowdsec_connector, "CROWDSEC_ENABLED", True)
    monkeypatch.setattr(crowdsec_connector, "CROWDSEC_ALLOWLIST_NAME", "test-list")
    monkeypatch.setattr(
        crowdsec_connector, "_get_crowdsec_ip_set_cached", lambda: set()
    )
    monkeypatch.setattr(
        crowdsec_connector, "_crowdsec_refresh_allowlist_ip_set", lambda: {"1.2.3.4"}
    )
    calls = []
    monkeypatch.setattr(
        crowdsec_connector,
        "run_cscli",
        lambda args: calls.append(args) or (0, "", ""),
    )
    crowdsec_connector.crowdsec_remove_ip("1.2.3.4")
    assert any("remove" in " ".join(c) for c in calls)


def test_remove_ip_all_retries_fail_no_raise(monkeypatch):
    """All removal retries fail — warning printed, no exception raised."""
    import crowdsec_connector

    monkeypatch.setattr(crowdsec_connector, "CROWDSEC_ENABLED", True)
    monkeypatch.setattr(crowdsec_connector, "CROWDSEC_ALLOWLIST_NAME", "test-list")
    monkeypatch.setattr(
        crowdsec_connector, "_get_crowdsec_ip_set_cached", lambda: {"1.2.3.4"}
    )
    monkeypatch.setattr(_time, "sleep", lambda s: None)
    monkeypatch.setattr(crowdsec_connector, "run_cscli", lambda args: (1, "", "error"))
    crowdsec_connector.crowdsec_remove_ip("1.2.3.4")  # must not raise


# ---------------------------------------------------------------------------
# LAPI mode — _write_lapi_config and _build_cscli_cmd
# ---------------------------------------------------------------------------


def test_lapi_mode_detected_when_url_and_login_set(monkeypatch):
    """_LAPI_MODE=True when CROWDSEC_LAPI_URL and CROWDSEC_LAPI_LOGIN are both set."""
    import importlib
    import crowdsec_connector as _cs

    monkeypatch.setenv("CROWDSEC_LAPI_URL", "http://crowdsec:8080")
    monkeypatch.setenv("CROWDSEC_LAPI_LOGIN", "pangolin-test")
    monkeypatch.setenv("CROWDSEC_LAPI_PASSWORD", "secret")
    cs = importlib.reload(_cs)
    assert cs._LAPI_MODE is True


def test_lapi_mode_not_set_when_url_missing(monkeypatch):
    """_LAPI_MODE=False when CROWDSEC_LAPI_URL is empty."""
    import importlib
    import crowdsec_connector as _cs

    monkeypatch.setenv("CROWDSEC_LAPI_URL", "")
    monkeypatch.setenv("CROWDSEC_LAPI_LOGIN", "pangolin-test")
    cs = importlib.reload(_cs)
    assert cs._LAPI_MODE is False


def test_lapi_mode_not_set_when_login_missing(monkeypatch):
    """_LAPI_MODE=False when CROWDSEC_LAPI_LOGIN is empty."""
    import importlib
    import crowdsec_connector as _cs

    monkeypatch.setenv("CROWDSEC_LAPI_URL", "http://crowdsec:8080")
    monkeypatch.setenv("CROWDSEC_LAPI_LOGIN", "")
    cs = importlib.reload(_cs)
    assert cs._LAPI_MODE is False


def test_lapi_mode_wins_over_cmd_prefix_with_warning(monkeypatch, capsys):
    """Both LAPI vars and CMD_PREFIX set — LAPI wins and a warning is printed."""
    import importlib
    import crowdsec_connector as _cs

    monkeypatch.setenv("CROWDSEC_LAPI_URL", "http://crowdsec:8080")
    monkeypatch.setenv("CROWDSEC_LAPI_LOGIN", "pangolin-test")
    monkeypatch.setenv("CROWDSEC_CMD_PREFIX", "docker exec crowdsec")
    cs = importlib.reload(_cs)
    assert cs._LAPI_MODE is True
    out = capsys.readouterr().out
    assert "WARNING" in out or "warning" in out.lower()
    assert "LAPI mode takes precedence" in out or "lapi" in out.lower()


def test_build_cscli_cmd_lapi_mode(monkeypatch):
    """LAPI mode: command is [cscli, -c, <config_path>] + args, no prefix."""
    import crowdsec_connector

    monkeypatch.setattr(crowdsec_connector, "_LAPI_MODE", True)
    monkeypatch.setattr(
        crowdsec_connector, "_LAPI_CONFIG_PATH", "/tmp/test-config.yaml"
    )
    result = crowdsec_connector._build_cscli_cmd(["allowlist", "list"])
    assert result == ["cscli", "-c", "/tmp/test-config.yaml", "allowlist", "list"]


def test_build_cscli_cmd_lapi_mode_ignores_cmd_prefix(monkeypatch):
    """LAPI mode: CMD_PREFIX is ignored even if set."""
    import crowdsec_connector

    monkeypatch.setattr(crowdsec_connector, "_LAPI_MODE", True)
    monkeypatch.setattr(
        crowdsec_connector, "_LAPI_CONFIG_PATH", "/tmp/test-config.yaml"
    )
    monkeypatch.setattr(
        crowdsec_connector, "CROWDSEC_CMD_PREFIX", "docker exec crowdsec"
    )
    result = crowdsec_connector._build_cscli_cmd(
        ["allowlist", "add", "mylist", "1.2.3.4"]
    )
    assert "docker" not in result
    assert result[0] == "cscli"
    assert "-c" in result


def test_write_lapi_config_creates_files(monkeypatch, tmp_path):
    """_write_lapi_config() creates both config and credentials files with correct content."""
    import crowdsec_connector

    cfg = str(tmp_path / "config.yaml")
    creds = str(tmp_path / "credentials.yaml")
    monkeypatch.setattr(crowdsec_connector, "_LAPI_CONFIG_PATH", cfg)
    monkeypatch.setattr(crowdsec_connector, "_LAPI_CREDENTIALS_PATH", creds)
    monkeypatch.setattr(crowdsec_connector, "CROWDSEC_LAPI_URL", "http://crowdsec:8080")
    monkeypatch.setattr(crowdsec_connector, "CROWDSEC_LAPI_LOGIN", "pangolin-test")
    monkeypatch.setattr(crowdsec_connector, "CROWDSEC_LAPI_PASSWORD", "s3cr3t")

    crowdsec_connector._write_lapi_config()

    assert (tmp_path / "config.yaml").exists()
    assert (tmp_path / "credentials.yaml").exists()


def test_write_lapi_config_credentials_content(monkeypatch, tmp_path):
    """Credentials file contains url, login, and password."""
    import crowdsec_connector

    cfg = str(tmp_path / "config.yaml")
    creds = str(tmp_path / "credentials.yaml")
    monkeypatch.setattr(crowdsec_connector, "_LAPI_CONFIG_PATH", cfg)
    monkeypatch.setattr(crowdsec_connector, "_LAPI_CREDENTIALS_PATH", creds)
    monkeypatch.setattr(crowdsec_connector, "CROWDSEC_LAPI_URL", "http://crowdsec:8080")
    monkeypatch.setattr(crowdsec_connector, "CROWDSEC_LAPI_LOGIN", "pangolin-test")
    monkeypatch.setattr(crowdsec_connector, "CROWDSEC_LAPI_PASSWORD", "s3cr3t")

    crowdsec_connector._write_lapi_config()

    content = (tmp_path / "credentials.yaml").read_text()
    assert "http://crowdsec:8080" in content
    assert "pangolin-test" in content
    assert "s3cr3t" in content


def test_write_lapi_config_password_not_in_config_file(monkeypatch, tmp_path):
    """Password must appear only in the credentials file, not in config.yaml."""
    import crowdsec_connector

    cfg = str(tmp_path / "config.yaml")
    creds = str(tmp_path / "credentials.yaml")
    monkeypatch.setattr(crowdsec_connector, "_LAPI_CONFIG_PATH", cfg)
    monkeypatch.setattr(crowdsec_connector, "_LAPI_CREDENTIALS_PATH", creds)
    monkeypatch.setattr(crowdsec_connector, "CROWDSEC_LAPI_URL", "http://crowdsec:8080")
    monkeypatch.setattr(crowdsec_connector, "CROWDSEC_LAPI_LOGIN", "pangolin-test")
    monkeypatch.setattr(crowdsec_connector, "CROWDSEC_LAPI_PASSWORD", "s3cr3t")

    crowdsec_connector._write_lapi_config()

    config_content = (tmp_path / "config.yaml").read_text()
    assert "s3cr3t" not in config_content


def test_write_lapi_config_references_credentials_path(monkeypatch, tmp_path):
    """config.yaml references the credentials file path."""
    import crowdsec_connector

    cfg = str(tmp_path / "config.yaml")
    creds = str(tmp_path / "credentials.yaml")
    monkeypatch.setattr(crowdsec_connector, "_LAPI_CONFIG_PATH", cfg)
    monkeypatch.setattr(crowdsec_connector, "_LAPI_CREDENTIALS_PATH", creds)
    monkeypatch.setattr(crowdsec_connector, "CROWDSEC_LAPI_URL", "http://crowdsec:8080")
    monkeypatch.setattr(crowdsec_connector, "CROWDSEC_LAPI_LOGIN", "pangolin-test")
    monkeypatch.setattr(crowdsec_connector, "CROWDSEC_LAPI_PASSWORD", "s3cr3t")

    crowdsec_connector._write_lapi_config()

    config_content = (tmp_path / "config.yaml").read_text()
    assert creds in config_content


def test_ensure_allowlist_calls_write_lapi_config_in_lapi_mode(monkeypatch, tmp_path):
    """In LAPI mode, ensure_allowlist writes the config before checking the allowlist."""
    import crowdsec_connector

    cfg = str(tmp_path / "config.yaml")
    creds = str(tmp_path / "credentials.yaml")
    monkeypatch.setattr(crowdsec_connector, "CROWDSEC_ENABLED", True)
    monkeypatch.setattr(crowdsec_connector, "_LAPI_MODE", True)
    monkeypatch.setattr(crowdsec_connector, "_LAPI_CONFIG_PATH", cfg)
    monkeypatch.setattr(crowdsec_connector, "_LAPI_CREDENTIALS_PATH", creds)
    monkeypatch.setattr(crowdsec_connector, "CROWDSEC_LAPI_URL", "http://crowdsec:8080")
    monkeypatch.setattr(crowdsec_connector, "CROWDSEC_LAPI_LOGIN", "pangolin-test")
    monkeypatch.setattr(crowdsec_connector, "CROWDSEC_LAPI_PASSWORD", "s3cr3t")
    monkeypatch.setattr(
        crowdsec_connector, "crowdsec_allowlist_exists", lambda name: True
    )

    crowdsec_connector.crowdsec_ensure_allowlist()

    assert (tmp_path / "config.yaml").exists()
    assert (tmp_path / "credentials.yaml").exists()


def test_ensure_allowlist_skips_write_lapi_config_in_docker_exec_mode(
    monkeypatch, tmp_path
):
    """In docker exec mode, ensure_allowlist does not write config files."""
    import crowdsec_connector

    cfg = str(tmp_path / "config.yaml")
    monkeypatch.setattr(crowdsec_connector, "CROWDSEC_ENABLED", True)
    monkeypatch.setattr(crowdsec_connector, "_LAPI_MODE", False)
    monkeypatch.setattr(crowdsec_connector, "_LAPI_CONFIG_PATH", cfg)
    monkeypatch.setattr(
        crowdsec_connector, "crowdsec_allowlist_exists", lambda name: True
    )

    crowdsec_connector.crowdsec_ensure_allowlist()

    assert not (tmp_path / "config.yaml").exists()


def test_add_ip_lapi_mode_passes_config_flag(monkeypatch):
    """In LAPI mode, the subprocess invocation includes the -c flag."""
    import subprocess
    import crowdsec_connector

    monkeypatch.setattr(crowdsec_connector, "CROWDSEC_ENABLED", True)
    monkeypatch.setattr(crowdsec_connector, "_LAPI_MODE", True)
    monkeypatch.setattr(
        crowdsec_connector, "_LAPI_CONFIG_PATH", "/tmp/test-config.yaml"
    )
    monkeypatch.setattr(crowdsec_connector, "CROWDSEC_ALLOWLIST_NAME", "test-list")
    monkeypatch.setattr(crowdsec_connector, "crowdsec_ensure_allowlist", lambda: None)
    monkeypatch.setattr(
        crowdsec_connector, "_crowdsec_ip_known_or_refresh", lambda ip: False
    )
    calls = []

    class _FakeProc:
        returncode = 0
        stdout = ""
        stderr = ""

    def _fake_run(cmd, **kwargs):
        calls.append(list(cmd))
        return _FakeProc()

    monkeypatch.setattr(subprocess, "run", _fake_run)
    crowdsec_connector.crowdsec_add_ip("1.2.3.4")
    assert calls, "subprocess.run should have been called"
    assert "-c" in calls[0]
    assert "/tmp/test-config.yaml" in calls[0]


def test_remove_ip_lapi_mode_passes_config_flag(monkeypatch):
    """In LAPI mode, the subprocess invocation includes the -c flag."""
    import subprocess
    import crowdsec_connector

    monkeypatch.setattr(crowdsec_connector, "CROWDSEC_ENABLED", True)
    monkeypatch.setattr(crowdsec_connector, "_LAPI_MODE", True)
    monkeypatch.setattr(
        crowdsec_connector, "_LAPI_CONFIG_PATH", "/tmp/test-config.yaml"
    )
    monkeypatch.setattr(crowdsec_connector, "CROWDSEC_ALLOWLIST_NAME", "test-list")
    monkeypatch.setattr(
        crowdsec_connector, "_get_crowdsec_ip_set_cached", lambda: {"1.2.3.4"}
    )
    calls = []

    class _FakeProc:
        returncode = 0
        stdout = ""
        stderr = ""

    def _fake_run(cmd, **kwargs):
        calls.append(list(cmd))
        return _FakeProc()

    monkeypatch.setattr(subprocess, "run", _fake_run)
    crowdsec_connector.crowdsec_remove_ip("1.2.3.4")
    assert calls, "subprocess.run should have been called"
    assert "-c" in calls[0]
    assert "/tmp/test-config.yaml" in calls[0]
