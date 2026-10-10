"""The agent's HTTP client: loopback-only, token and error hygiene, error mapping. A fake transport stands in for the network."""
import http.client
import json

import pytest

from agent.client import BackendClient, BackendError, Unreachable, parse_server_url

RUN = "a" * 32
TOKEN = "0123456789abcdef" * 2


def client_with(responder):
    calls = []

    def transport(method, path, headers, body):
        calls.append((method, path, dict(headers), body))
        return responder(method, path, headers, body)

    return BackendClient("http://127.0.0.1:8765", transport=transport), calls


def ok(payload):
    return lambda *a: (200, json.dumps(payload).encode())


# ----------------------------------------------------------------------------- only loopback servers
@pytest.mark.parametrize("url", ["http://127.0.0.1:8765", "http://localhost:9000", "http://127.0.0.1", "http://127.0.0.1:8765/"])
def test_loopback_urls_are_accepted(url):
    host, port = parse_server_url(url)
    assert host in ("127.0.0.1", "localhost") and 0 < port < 65536


@pytest.mark.parametrize("url", [
    "https://127.0.0.1:8765", "http://example.com:8765", "http://192.168.1.5:8765", "http://0.0.0.0:8765", "http://[::1]:8765",
    "http://127.0.0.1.evil.com:8765", "http://user:pw@127.0.0.1:8765", "http://127.0.0.1:8765/api", "http://127.0.0.1:8765?x=1",
    "http://127.0.0.1:99999", "ftp://127.0.0.1", "", "127.0.0.1:8765", "//127.0.0.1:8765",
])
def test_everything_else_is_refused(url):
    with pytest.raises(ValueError):
        parse_server_url(url)


def test_a_non_string_url_is_refused():
    with pytest.raises(ValueError):
        parse_server_url(None)


# ----------------------------------------------------------------------------- requests
def test_listing_asks_for_queued_filesystem_runs_only():
    client, calls = client_with(ok({"runs": [{"run_id": RUN, "run_number": 3}, "junk", {"no_id": 1}]}))
    assert client.queued_filesystem_runs(limit=7) == [{"run_id": RUN, "run_number": 3}]
    assert calls[0][:2] == ("GET", "/api/runs?type=filesystem&status=queued&limit=7") and calls[0][3] is None


def test_claim_sends_identity_and_no_token():
    client, calls = client_with(ok({"lease_token": TOKEN}))
    client.claim(RUN, agent_id="agent-x", hostname="HOST", os_name="Windows", agent_version="0.1.0")
    method, path, headers, body = calls[0]
    assert (method, path) == ("POST", f"/api/runs/{RUN}/claim")
    assert json.loads(body) == {"agent_id": "agent-x", "hostname": "HOST", "os": "Windows", "agent_version": "0.1.0"}
    assert "X-Run-Token" not in headers


def test_the_token_travels_only_in_the_header():
    client, calls = client_with(ok({"status": "running"}))
    client.heartbeat(RUN, TOKEN)
    client.upload(RUN, TOKEN, [[0, {"a": 1}]])
    client.finish(RUN, TOKEN, outcome="finished", summary={"x": 1})
    for method, path, headers, body in calls:
        assert headers["X-Run-Token"] == TOKEN
        assert TOKEN not in path and (body is None or TOKEN.encode() not in body)
    assert json.loads(calls[1][3]) == {"items": [[0, {"a": 1}]]}
    assert json.loads(calls[2][3]) == {"outcome": "finished", "summary": {"x": 1}, "fatal_code": None}


def test_body_is_ascii_json_even_for_unicode_content():
    client, calls = client_with(ok({}))
    client.upload(RUN, TOKEN, [[0, {"name": "café \U0001F512"}]])
    body = calls[0][3]
    body.decode("ascii")
    assert json.loads(body)["items"][0][1]["name"] == "café \U0001F512"


@pytest.mark.parametrize("bad", ["", "xyz", "A" * 32, "a" * 31, "a" * 33, "../../etc", None, 5])
def test_malformed_run_ids_never_reach_a_url(bad):
    client, calls = client_with(ok({}))
    with pytest.raises(ValueError):
        client.heartbeat(bad, TOKEN)
    assert calls == []


@pytest.mark.parametrize("bad", ["", "short", "G" * 32, TOKEN + "0", "abc\r\nX-Evil: 1"])
def test_malformed_tokens_never_reach_a_header(bad):
    client, calls = client_with(ok({}))
    with pytest.raises(ValueError) as excinfo:
        client.heartbeat(RUN, bad)
    assert calls == [] and (bad == "" or bad not in str(excinfo.value))


def test_non_finite_numbers_cannot_be_sent():
    client, calls = client_with(ok({}))
    with pytest.raises(ValueError):
        client.finish(RUN, TOKEN, outcome="finished", summary={"x": float("nan")})
    assert calls == []


# ----------------------------------------------------------------------------- errors
def test_error_envelope_becomes_a_backend_error_with_a_code():
    body = {"error": {"code": "lease_overdue", "message": f"secret {TOKEN}", "details": {"run": {"status": "partial"}}}}
    client, _ = client_with(lambda *a: (409, json.dumps(body).encode()))
    with pytest.raises(BackendError) as excinfo:
        client.heartbeat(RUN, TOKEN)
    err = excinfo.value
    assert (err.status, err.code, err.details) == (409, "lease_overdue", {"run": {"status": "partial"}})
    assert TOKEN not in str(err) and "secret" not in str(err)                      # the server's message is never copied


@pytest.mark.parametrize("body", [b"", b"<html>nope</html>", b"[]", b'{"error": "text"}', b'{"error": {"code": "Bad Code!"}}',
                                  b'{"error": {"code": 5}}', b'{"error": {"code": "' + b"a" * 100 + b'"}}'])
def test_unrecognizable_error_bodies_map_to_unknown_error(body):
    client, _ = client_with(lambda *a: (500, body))
    with pytest.raises(BackendError) as excinfo:
        client.heartbeat(RUN, TOKEN)
    assert excinfo.value.status == 500 and excinfo.value.code == "unknown_error" and excinfo.value.details == {}


@pytest.mark.parametrize("body", [b"", b"not json", b"[1]", b"null"])
def test_a_success_without_a_json_object_is_an_error(body):
    client, _ = client_with(lambda *a: (200, body))
    with pytest.raises(BackendError) as excinfo:
        client.heartbeat(RUN, TOKEN)
    assert excinfo.value.code == "invalid_response"


def test_listing_without_a_runs_list_is_an_error():
    client, _ = client_with(ok({"runs": "nope"}))
    with pytest.raises(BackendError):
        client.queued_filesystem_runs()


@pytest.mark.parametrize("exc", [ConnectionRefusedError("boom"), TimeoutError(), OSError("net down"), http.client.RemoteDisconnected("x"),
                                 http.client.IncompleteRead(b"")])
def test_network_failures_become_unreachable_without_leaking_detail(exc):
    def broken(*a):
        raise exc

    client, _ = client_with(broken)
    with pytest.raises(Unreachable) as excinfo:
        client.upload(RUN, TOKEN, [[0, {"secret": "value"}]])
    assert type(exc).__name__ in str(excinfo.value) and "value" not in str(excinfo.value)
    assert excinfo.value.__cause__ is None                                         # the original (which may quote a path) is dropped


def test_nothing_is_listening_means_unreachable():
    import socket
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]                                                  # closed again: nothing listens here
    with pytest.raises(Unreachable):
        BackendClient(f"http://127.0.0.1:{port}", timeout=2).queued_filesystem_runs()


def test_an_unexpected_exception_type_is_not_swallowed():
    def broken(*a):
        raise KeyError("bug")

    client, _ = client_with(broken)
    with pytest.raises(KeyError):
        client.heartbeat(RUN, TOKEN)


def test_queued_runs_asks_once_for_every_queued_run_and_keeps_only_types_the_agent_can_run():
    runs = [{"run_id": RUN, "run_number": 3, "type": "tls"}, {"run_id": "b" * 32, "run_number": 2, "type": "filesystem"},
            {"run_id": "c" * 32, "run_number": 1, "type": "capture"}, {"run_number": 9, "type": "tls"}, "junk"]
    client, calls = client_with(ok({"runs": runs}))
    assert [r["run_number"] for r in client.queued_runs(limit=7)] == [3, 2]
    assert [c[:2] for c in calls] == [("GET", "/api/runs?status=queued&limit=7")] and calls[0][3] is None


def test_queued_runs_rejects_a_body_without_a_runs_list():
    client, _ = client_with(ok({"runs": "nope"}))
    with pytest.raises(BackendError):
        client.queued_runs()
