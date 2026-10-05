"""Controlled JSON/text HTTP calls through an owned, cancellable network worker."""

import json
from urllib.parse import urlsplit
from bloxsmith_app.block_api import APPLICATION_JSON, BlockDefinition, BlockRuntimeOutput, BlockRuntimePreparation, BlockRuntimeResult
from . import engine, policy, ui


# FB1 - Restrict inputs to a configured origin/path, allowed methods and bounded JSON/text contracts.
# FB2 - Pin verified DNS addresses, enforce network/TLS policy and keep credentials in the wallet/pipe.
# FB3 - Bound total I/O, redirects/pages and cancellation; never retry a potentially applied mutation.
# FB4 - Return structured responses or explicit diagnostics through both runtimes and package origins.
# FB5 - Own translated responsive settings, draft validation and static release-scoped assets.
class HttpRequestBlock(BlockDefinition):
    """Response bodies are untrusted data, never executable HTML or instructions."""

    kind = "http_request"

    def ui_assets(self, surface="modal"):
        """Every installation uses the same release manifest."""
        return list(self.model.get("ui_assets", {}).get(surface, []))

    def prepare_runtime(self, context):
        """Validate authored policy without network, wallet or filesystem effects."""
        policy.configuration(context.config)
        return BlockRuntimePreparation()

    def execute_runtime(self, context):
        """One input message makes one bounded call chain, with no implicit retry."""
        try:
            if context.input_events:
                if len(context.input_events) != 1:
                    raise policy.HttpError("request", "One request per activation is required; no batched mutation was sent.")
                ports = {int(port.id): str(port.name) for port in context.input_ports}
                event = context.input_events[0]
                if ports.get(event.input_port_id) != "request":
                    raise policy.HttpError("request", "Unknown input port.")
                value = event.value
            else:
                if not context.has_input_value("request", "1"):
                    return BlockRuntimeResult(status="skipped", outputs=[])
                value = context.input_value("request", "1")
            values = engine.execute(value, context.config, {
                "resolve_secret": context.resolve_secret,
                "cancel_requested": context.services.get("cancel_requested", lambda: False)})
        except policy.HttpError as exc:
            values = {"error": exc.envelope()}
        except (ValueError, TypeError, OSError, RuntimeError):
            # No raw network, provider, path or credential-bearing exceptions in public output.
            values = {"error": {"code": "internal", "message": "The HTTP operation failed without a complete result.",
                                "ambiguous": True, "retry_performed": False}}
        outputs = [BlockRuntimeOutput(port_id=int(port.id), port_name=port.name,
            value=(context.redact_secrets(json.dumps(values[port.name], ensure_ascii=False, allow_nan=False))
                   if port.name == "error" else json.dumps(values[port.name], ensure_ascii=False, allow_nan=False)), content_type=APPLICATION_JSON)
            for port in context.output_ports if port.name in values]
        failed = "error" in values
        return BlockRuntimeResult(status="success", outputs=outputs,
            metadata={self.kind: {"status": "error" if failed else "ready",
                "pages": len(values.get("response", {}).get("pages", [])),
                "error_code": values.get("error", {}).get("code", "")}},
            logs=[context.redact_secrets("[http-request] Call completed with diagnostics." if failed else "[http-request] Call completed.")])

    def handle_ui_action(self, *, node, action, values, payload=None):
        """Apply validates policy, never probes the endpoint or reveals the secret."""
        if action in {"save_settings", "modal_update_fields", "inspector_update_fields"}:
            patch = (values or {}).get("node_patch") or {}
            if "config" in patch:
                try:
                    policy.configuration({**self.default_config(), **(node.get("config") or {}), **patch["config"]})
                except (ValueError, TypeError) as exc:
                    detail = str(exc) if isinstance(exc, policy.HttpError) else "Invalid HTTP settings."
                    return {"error": self.translate("block.http_request.error", {"detail": detail}, fallback="HTTP request failed: {detail}")}
        result = super().handle_ui_action(node=node, action="modal_update_fields" if action == "save_settings" else action,
                                          values=values, payload=payload)
        return ui.replace_config(result, node)

    def render_modal(self, *, node, payload=None):
        """Credentials are references, and advanced network permissions are separate."""
        return ui.modal(self, node, payload)

    def render_inspector_panel(self, *, node, payload=None):
        """Use the same owned draft and validation in the inspector."""
        return ui.inspector(self, node, payload)

    def render_node_card(self, *, node, payload=None):
        """Display only the configured host, never URL query data or a token."""
        try:
            host = urlsplit((node.get("config") or {}).get("base_url", policy.DEFAULTS["base_url"])).hostname or ""
        except ValueError:
            host = ""
        return ui.card(self, node, host)
