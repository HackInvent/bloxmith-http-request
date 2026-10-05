"""FB1/FB2/FB3/FB4: actual bounded HTTP/HTTPS, wallet pipes, DNS policy and cancellation."""

import json
from pathlib import Path
import socket
import sys
import tempfile
import time
from types import SimpleNamespace
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[3]
sys.path[:0] = [str(ROOT), str(ROOT / "tests"), str(Path(__file__).resolve().parent)]
from blocs.http_request import policy, engine, http_worker
from blocs.http_request.block import HttpRequestBlock
from bloxsmith_app.block_api import BlockRuntimeContext
from http_fixture import api_fixture


def rejected(call, code=None):
    """Validation must reject before a network operation, not produce an empty success."""
    try:
        call()
    except policy.HttpError as exc:
        if code:
            assert exc.code == code, (code, exc.code)
        return exc
    raise AssertionError("Invalid request accepted")


def main():
    """The only network peers are owned disposable loopback fixtures."""
    config = policy.configuration({})
    for raw in ({"base_url": "https://user:password@example.invalid/"},
                {"base_url": "https://example.invalid:0/"}, {"base_url": "http://example.invalid/"},
                {"base_url": "https://example.invalid/a/../b"}, {"allowed_methods": ["GET", "GET"]},
                {"auth_mode": "bearer"}, {"auth_header": "Host"}, {"auth_header": "Cookie"},
                {"timeout_sec": True}, {"max_pages": 9}, {"unknown": 1}):
        rejected(lambda: policy.configuration(raw))
    for value in ({"path": "../outside"}, {"path": "%2e%2e/x"}, {"path": "%252e%252e/x"},
                  {"path": "//evil.invalid/x"}, {"path": "/x?y=z"}, {"headers": {"Authorization": "x"}},
                  {"method": "DELETE"}, {"query": {"nested": []}}, {"body": {"x": 1}},
                  '{"path":"x","path":"y"}'):
        rejected(lambda: policy.request(value, config))
    assert policy.request({"path": "/ok"}, {**config, "base_url": "https://example.invalid/v1/"})["url"] == "https://example.invalid/v1/ok"
    for address in ("127.0.0.1", "::1", "169.254.169.254", "100.100.100.200", "224.0.0.1", "0.0.0.0"):
        assert not policy.address_allowed(address, config)
    private = {**config, "allow_private_network": True}
    for address in ("127.0.0.1", "::1", "fc00::1", "::ffff:127.0.0.1"):
        assert policy.address_allowed(address, private)
    # Exercise both ends of every declared LAN range, never a developer's network coordinate.
    for network in policy.PRIVATE:
        for address in (str(network[1]), str(network[-2])):
            assert not policy.address_allowed(address, config)
            assert policy.address_allowed(address, private)
    for address in ("169.254.169.254", "100.100.100.200", "224.0.0.1", "0.0.0.0"):
        assert not policy.address_allowed(address, private)
    with patch.object(http_worker.socket, "getaddrinfo", return_value=[
        (socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", ("169.254.169.254", 443))]),          patch.object(http_worker.socket, "socket") as socket_factory:
        rejected(lambda: http_worker.connect(config, config["base_url"], time.monotonic() + 1), "destination")
        socket_factory.assert_not_called()
    with api_fixture() as api:
        cfg = {**config, "base_url": api.base_url, "allow_private_network": True, "allow_insecure_http": True}
        def call(path, **options):
            return engine.execute({"path": path}, {**cfg, **options}, {})
        ok = call("ok")
        assert ok["response"]["http_ok"] and ok["response"]["pages"][0]["body"] == {"ok": True}
        assert "set-cookie" not in ok["response"]["pages"][0]["headers"]
        assert call("text")["response"]["pages"][0]["body"] == "Café fixture"
        head = engine.execute({"method": "HEAD", "path": "ok"}, cfg, {})
        assert head["response"]["pages"][0]["body"] is None
        pages = call("page", max_pages=2)["response"]
        assert [page["body"]["page"] for page in pages["pages"]] == [1, 2] and pages["complete"]
        limited = call("page")["response"]
        assert not limited["complete"] and limited["next_available"] and len(limited["pages"]) == 1
        assert call("next-outside", max_pages=2)["error"]["code"] == "destination"
        before = len(api.calls)
        assert call("redirect-outside", follow_redirects=True)["error"]["code"] == "destination"
        assert len(api.calls) == before + 1
        redirected = call("redirect", follow_redirects=True)["response"]
        assert redirected["redirects_followed"] == 1 and redirected["http_ok"]
        before = len(api.calls)
        write = engine.execute({"method": "POST", "path": "redirect", "body": {"x": 1}},
            {**cfg, "allowed_methods": ["POST"], "follow_redirects": True}, {})
        assert write["response"]["pages"][0]["status"] == 302 and len(api.calls) == before + 1
        failed = call("error")
        assert failed["response"]["pages"][0]["status"] == 503 and not failed["error"]["retry_performed"]
        assert call("large", max_response_bytes=1024)["error"]["code"] == "response_limit"
        assert call("duplicate")["error"]["code"] == "response"
        assert call("compressed")["error"]["code"] == "encoding"
        assert call("binary")["error"]["code"] == "content_type"
        assert call("truncated")["error"]["code"] in {"response", "transport"}
        assert call("ok", allow_private_network=False)["error"]["code"] == "destination"
        started = time.monotonic()
        error = rejected(lambda: engine.execute({"path": "slow"}, {**cfg, "timeout_sec": 1}, {}), "timeout")
        assert not error.ambiguous and time.monotonic() - started < 2.5
        started = time.monotonic()
        error = rejected(lambda: engine.execute({"method": "POST", "path": "slow", "body": {}},
            {**cfg, "allowed_methods": ["POST"]}, {"cancel_requested": lambda: time.monotonic() - started > .3}), "cancelled")
        assert error.ambiguous and time.monotonic() - started < 2
        # A real source value follows the public helper; diagnostics never echo its value.
        block = HttpRequestBlock()
        out = (SimpleNamespace(id=8, name="response"), SimpleNamespace(id=6, name="error"))
        result = block.execute_runtime(BlockRuntimeContext(config=cfg, inputs={"request": '{"path":"ok"}'},
            input_ports=(SimpleNamespace(id=1, name="request"),), output_ports=out))
        assert result.status == "success" and result.outputs[0].port_id == 8
        # Block a resolver inside the real owned child. Parent timeout must reap it.
        with tempfile.TemporaryDirectory() as folder:
            directory = Path(folder)
            worker = Path(engine.__file__).with_name("http_worker.py")
            (directory / "http_worker.py").write_text(
                "import socket,time,runpy\n"
                "socket.getaddrinfo=lambda *a,**k: time.sleep(30)\n"
                + "runpy.run_path(" + repr(str(worker)) + ",run_name='__main__')\n", encoding="utf-8")
            children, original = [], engine.subprocess.Popen
            def capture(*args, **kwargs):
                child = original(*args, **kwargs)
                children.append(child)
                return child
            previous_calls = len(api.calls)
            with patch.object(engine, "__file__", str(directory / "engine.py")), patch.object(engine.subprocess, "Popen", side_effect=capture):
                rejected(lambda: engine.execute({"path": "ok"}, {**cfg, "timeout_sec": 1}, {}), "timeout")
            assert children and all(child.poll() is not None for child in children)
            assert len(api.calls) == previous_calls
    with api_fixture(tls=True) as api:
        cfg = {**config, "base_url": api.base_url, "allow_private_network": True, "ca_file": api.ca_file,
               "auth_mode": "bearer", "secret_ref": "secret://workspace/fixture"}
        refs = []
        def resolve(ref):
            refs.append(ref)
            return "fixture-dummy-token"
        result = engine.execute({"path": "auth"}, cfg, {"resolve_secret": resolve})
        assert result["response"]["pages"][0]["body"]["authenticated"] is True
        assert refs == ["secret://workspace/fixture"]
        result = engine.execute({"path": "auth"}, {**cfg, "auth_mode": "header"}, {"resolve_secret": resolve})
        assert result["response"]["pages"][0]["body"]["custom_header"] is True
        result = engine.execute({"path": "echo-secret"}, cfg, {"resolve_secret": resolve})
        assert result["error"]["code"] == "secret_echo" and "response" not in result
        assert "fixture-dummy-token" not in json.dumps(result)
        untrusted = engine.execute({"path": "auth"}, {**cfg, "ca_file": ""}, {"resolve_secret": resolve})
        assert untrusted["error"]["code"] == "transport"
        rejected(lambda: engine.execute({"path": "auth"}, cfg, {}), "secret")
    print("[ok] HTTP Request real HTTP/HTTPS, destination/TLS policy, bounded transport and wallet isolation")


if __name__ == "__main__":
    main()
