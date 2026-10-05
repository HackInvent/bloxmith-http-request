"""Own one cancellable Python network process; never put credentials in command lines."""

import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import time

from . import policy


def stop(child):
    """Terminate and reap only this process group, including a blocked DNS resolver."""
    if child.poll() is None:
        try:
            os.killpg(child.pid, signal.SIGTERM)
        except ProcessLookupError:
            pass
        try:
            child.wait(timeout=0.2)
        except subprocess.TimeoutExpired:
            try:
                os.killpg(child.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
    child.wait(timeout=1)


def execute(value, raw_config, services):
    """Validate, resolve one wallet token, then enforce a total network-operation deadline."""
    config = policy.configuration(raw_config)
    request = policy.request(value, config)
    cancel = services.get("cancel_requested", lambda: False)
    if cancel():
        raise policy.HttpError("cancelled", "HTTP request cancelled before transmission.")
    token = ""
    if config["auth_mode"] != "none":
        resolver = services.get("resolve_secret")
        if not callable(resolver):
            raise policy.HttpError("secret", "The wallet secret service is unavailable.")
        try:
            token = policy.secret_value(resolver(config["secret_ref"]))
        except Exception:
            raise policy.HttpError("secret", "The wallet credential is unavailable or invalid.") from None
    if cancel():
        raise policy.HttpError("cancelled", "HTTP request cancelled before transmission.")
    payload = policy.encoded({"config": config, "request": request, "token": token}, 12582912)
    worker = Path(__file__).with_name("http_worker.py")
    child = subprocess.Popen([sys.executable, "-I", "-B", "-u", str(worker)], stdin=subprocess.PIPE,
        stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, start_new_session=True,
        env={"PATH": os.defpath, "PYTHONIOENCODING": "utf-8", "PYTHONDONTWRITEBYTECODE": "1"})
    deadline = time.monotonic() + config["timeout_sec"]
    mutation = request["method"] not in {"GET", "HEAD", "OPTIONS"}
    try:
        first = True
        while True:
            if cancel():
                raise policy.HttpError("cancelled", "HTTP request cancelled; verify remote state before retrying a mutation.",
                                       ambiguous=mutation)
            if time.monotonic() >= deadline:
                raise policy.HttpError("timeout", "HTTP deadline exceeded; no request was retried.", ambiguous=mutation)
            try:
                output, _ = child.communicate(input=payload if first else None, timeout=min(.1, max(.001, deadline - time.monotonic())))
                break
            except subprocess.TimeoutExpired:
                first = False
        if child.returncode != 0 or len(output) > 33554432:
            raise policy.HttpError("worker", "The HTTP worker did not return a complete bounded result.", ambiguous=mutation)
        result = json.loads(output)
        policy.encoded(result, 33554432)
        if not isinstance(result, dict) or set(result) - {"response", "error"} or not result:
            raise policy.HttpError("worker", "The HTTP worker returned an invalid result.", ambiguous=mutation)
        if cancel():
            raise policy.HttpError("cancelled", "HTTP result discarded after cancellation; verify remote state.", ambiguous=mutation)
        return result
    finally:
        stop(child)
        if child.stdin:
            child.stdin.close()
        if child.stdout:
            child.stdout.close()
