"""FB1/FB2/FB3/FB4/FB5: real HTTPS, isolated wallet and both runtimes/package origins."""

from pathlib import Path
import json
import sys

ROOT = Path(__file__).resolve().parents[3]
sys.path[:0] = [str(ROOT), str(ROOT / "tests"), str(Path(__file__).resolve().parent)]
from blocs.http_request.block import HttpRequestBlock
from block_test_packages import install_test_package, surface_payload
from ui_smoke_common import create_project_api, create_run_api, data_edge, display_node, graph_payload, http_json, isolated_server, text_node, wait_for_run_terminal
from http_fixture import api_fixture


def main():
    """Only fixture credentials are initialized, in newly created disposable app storage."""
    block = HttpRequestBlock()
    with api_fixture(tls=True) as api:
        for mode in ("centralized", "zeromq_active"):
            for origin in (None, "managed", "linked"):
                with isolated_server() as server:
                    node = block.build_node_payload(node_id="request", position={"x": 360, "y": 140})
                    node["config"] = {**block.default_config(), "base_url": api.base_url,
                        "allow_private_network": True, "ca_file": api.ca_file,
                        "auth_mode": "bearer", "secret_ref": "secret://workspace/fixture_http"}
                    if origin:
                        model = install_test_package(server, "http_request", origin=origin)
                        node["block_version"] = model["version"]
                        for surface in ("modal", "inspector_panel", "node_card"):
                            html = surface_payload(server, model, node, surface=surface)["html"]
                            assert "{{" not in html and "fixture-dummy-token" not in html
                            if surface != "node_card":
                                assert 'data-block-config-field="base_url"' in html
                    http_json(server.base_url, "/api/application/secrets/init", method="POST",
                              payload={"password": "disposable-http-fixture"})
                    http_json(server.base_url, "/api/application/secrets", method="POST",
                              payload={"name": "fixture_http", "value": "fixture-dummy-token"})
                    graph = graph_payload("Controlled HTTPS", [
                        text_node("source", "Request", '{"id":"fixture","path":"auth"}', 60, 140), node,
                        display_node("response", "Response", 700, 140), display_node("diagnostic", "Error", 700, 340)], [
                        data_edge("input", "source", 1, "request", 1), data_edge("response", "request", 1, "response", 1),
                        data_edge("error", "request", 2, "diagnostic", 1)])
                    project = create_project_api(server, document=graph)["project"]
                    run = create_run_api(server, graph, project_id=project["graph_id"], runtime_mode=mode)
                    result = wait_for_run_terminal(server, run["run_id"], timeout_sec=30)
                    assert result["status"] == "success", (mode, origin, result.get("logs"))
                    assert "request:1" in result["output_values"], (mode, origin, result.get("output_values"))
                    value = json.loads(result["output_values"]["request:1"]["value"])
                    assert value["pages"][0]["body"]["authenticated"], value
                    assert value["id"] == "fixture" and value["http_ok"]
                    assert "fixture-dummy-token" not in json.dumps(result)
                    # A locked fixture wallet cannot silently reuse a cached token or plaintext config.
                    http_json(server.base_url, "/api/application/secrets/lock", method="POST", payload={})
                    previous_calls = len(api.calls)
                    run = create_run_api(server, graph, project_id=project["graph_id"], runtime_mode=mode)
                    denied = wait_for_run_terminal(server, run["run_id"], timeout_sec=30)
                    assert denied["status"] == "success", (mode, origin, denied.get("logs"))
                    error = json.loads(denied["output_values"]["request:2"]["value"])
                    assert error["code"] == "secret" and len(api.calls) == previous_calls
                    assert "fixture-dummy-token" not in json.dumps(denied)
                print("[ok] HTTP Request HTTPS + wallet " + mode + " " + str(origin), flush=True)


if __name__ == "__main__":
    main()
