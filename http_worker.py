"""Short-lived network worker: DNS and all I/O are covered by the parent process deadline."""

import http.client
import ipaddress
import json
import os
from pathlib import Path
import re
import resource
import socket
import ssl
import stat
import sys
import time
from urllib.parse import urlsplit

if __package__:
    from .policy import HttpError, address_allowed, configuration, destination, encoded, fail, origin, secret_value
else:
    # -I intentionally removes package search paths; only this trusted release is added.
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    from policy import HttpError, address_allowed, configuration, destination, encoded, fail, origin, secret_value

RETURN_HEADERS = {"content-type", "etag", "last-modified", "retry-after", "content-language"}
SAFE = {"GET", "HEAD", "OPTIONS"}


def remaining(deadline):
    """Socket operations cannot extend the worker's shared wall-clock budget."""
    result = deadline - time.monotonic()
    if result <= 0:
        fail("timeout", "HTTP deadline exceeded.")
    return max(0.001, result)


def next_link(header):
    """Support bounded standard Link entries; reject ambiguity rather than guessing a URL."""
    if not header:
        return None
    if len(header) > 8192:
        fail("pagination", "Link header exceeds its size limit.")
    # Split at commas outside angle brackets or quoted parameters.
    parts, current, angle, quote_mode, escaped = [], [], False, False, False
    for char in header:
        if escaped:
            escaped = False
        elif quote_mode and char == "\\":
            escaped = True
        elif char == '"' and not angle:
            quote_mode = not quote_mode
        elif char == "<" and not quote_mode:
            if angle:
                fail("pagination", "Malformed Link header.")
            angle = True
        elif char == ">" and not quote_mode:
            angle = False
        if char == "," and not angle and not quote_mode:
            parts.append("".join(current).strip()); current = []
        else:
            current.append(char)
    parts.append("".join(current).strip())
    if quote_mode or angle or len(parts) > 32:
        fail("pagination", "Malformed or oversized Link header.")
    found = []
    for part in parts:
        match = re.fullmatch(r'<([^<>]+)>((?:\s*;\s*[A-Za-z0-9_-]+\s*=\s*(?:"[^"\\]*"|[A-Za-z0-9_./:-]+))*)\s*', part)
        if not match:
            fail("pagination", "Unsupported Link header syntax.")
        attributes = re.findall(r';\s*([A-Za-z0-9_-]+)\s*=\s*("[^"]*"|[A-Za-z0-9_./:-]+)', match.group(2))
        params = {}
        for name, value in attributes:
            name = name.lower()
            if name in params:
                fail("pagination", "Duplicate Link parameter.")
            params[name] = value.strip('"')
        if "next" in params.get("rel", "").split():
            if "anchor" in params:
                fail("pagination", "Anchored next links are unsupported.")
            found.append(match.group(1))
    if len(found) > 1:
        fail("pagination", "Several next links are ambiguous.")
    return found[0] if found else None


def tls_context(config):
    """Verify both chain and hostname; there is no insecure TLS option."""
    ca = config["ca_file"]
    if ca:
        path = Path(ca)
        if not path.is_file() or path.is_symlink() or path.stat().st_size > 1048576:
            fail("tls", "The configured CA file is unavailable or oversized.")
        return ssl.create_default_context(cafile=str(path))
    return ssl.create_default_context()


def connect(config, url, deadline):
    """Resolve once, check every address, then connect a numeric socket without DNS rebinding."""
    parsed, (scheme, host, port) = origin(url)
    addresses = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM, proto=socket.IPPROTO_TCP)
    if not addresses or len(addresses) > 32 or any(not address_allowed(item[4][0], config) for item in addresses):
        fail("destination", "The destination resolved to a forbidden or excessive address set.")
    context = tls_context(config) if scheme == "https" else None
    sock = None
    for family, socktype, proto, _, sockaddr in addresses[:4]:
        remaining(deadline)
        candidate = socket.socket(family, socktype, proto)
        candidate.settimeout(remaining(deadline))
        try:
            candidate.connect(sockaddr)
            sock = candidate
            break
        except OSError:
            candidate.close()
    if sock is None:
        fail("connect", "Unable to connect to the configured destination.")
    try:
        if context:
            sock.settimeout(remaining(deadline))
            sock = context.wrap_socket(sock, server_hostname=host)
        connection = http.client.HTTPConnection(host, port, timeout=remaining(deadline))
        connection.sock = sock
        return connection
    except BaseException:
        sock.close()
        raise


def call(config, request, token, url, budget, deadline):
    """A single attempt; no automatic mutation retry, response decompression or cookie jar."""
    connection = connect(config, url, deadline)
    try:
        headers = {"Accept": "application/json, text/plain, text/*;q=0.8",
                   "Accept-Encoding": "identity", "User-Agent": "BloxSmith-HTTP-Request/0.1.0", "Connection": "close"}
        if token:
            headers["Authorization" if config["auth_mode"] == "bearer" else config["auth_header"]] = (
                "Bearer " + token if config["auth_mode"] == "bearer" else token)
        body = request["body"].encode("utf-8") if request["body"] is not None else None
        if request["content_type"]:
            headers["Content-Type"] = request["content_type"]
        parsed = urlsplit(url)
        target = parsed.path or "/"
        if parsed.query:
            target += "?" + parsed.query
        connection.sock.settimeout(remaining(deadline))
        connection.request(request["method"], target, body=body, headers=headers)
        connection.sock.settimeout(remaining(deadline))
        response = connection.getresponse()
        pairs = response.getheaders()
        if sum(len(k) + len(v) for k, v in pairs) > 32768:
            fail("headers_limit", "Response headers exceed the limit.")
        collected = {}
        for key, value in pairs:
            name = key.lower()
            if name in collected and name in {"content-length", "content-type", "content-encoding", "location"}:
                fail("response", "Ambiguous response headers.")
            collected[name] = collected[name] + ", " + value if name in collected else value
        if "content-length" in collected and "transfer-encoding" in collected:
            fail("response", "Ambiguous response framing.")
        length = collected.get("content-length")
        if length is not None and (not re.fullmatch(r"[0-9]{1,12}", length) or (request["method"] != "HEAD" and response.status not in {204, 304} and int(length) > budget)):
            fail("response_limit", "Response body exceeds the remaining byte limit.")
        if collected.get("content-encoding", "identity").lower() != "identity":
            fail("encoding", "Compressed responses are not supported; identity encoding was requested.")
        chunks, total = [], 0
        while True:
            # HTTPResponse keeps its own file object after Connection: close detaches sock.
            raw_socket = connection.sock
            if raw_socket is not None:
                raw_socket.settimeout(remaining(deadline))
            remaining(deadline)
            part = response.read1(min(65536, budget - total + 1))
            if not part:
                break
            total += len(part)
            if total > budget:
                fail("response_limit", "Response body exceeds the remaining byte limit.")
            chunks.append(part)
        raw = b"".join(chunks)
        if request["method"] != "HEAD" and response.status not in {204, 304} and length is not None and len(raw) != int(length):
            fail("response", "The HTTP response ended before its declared length.")
        media = collected.get("content-type", "").split(";", 1)[0].strip().lower()
        if not raw:
            body = None
        else:
            if media != "application/json" and not media.endswith("+json") and not media.startswith("text/"):
                fail("content_type", "Only JSON and text response bodies are supported.")
            text = raw.decode("utf-8", errors="strict")
            if media == "application/json" or media.endswith("+json"):
                def pairs(items):
                    result = {}
                    for key, value in items:
                        if key in result:
                            fail("response", "Duplicate JSON response property.")
                        result[key] = value
                    return result
                body = json.loads(text, object_pairs_hook=pairs)
                encoded(body, config["max_response_bytes"])
            else:
                body = text
        page = {"status": response.status, "headers": {k: v for k, v in collected.items() if k in RETURN_HEADERS},
                "content_type": media, "body": body, "body_bytes": total}
        if token:
            pending = [body, collected]
            while pending:
                item = pending.pop()
                if isinstance(item, dict):
                    pending.extend(item.keys())
                    pending.extend(item.values())
                elif isinstance(item, list):
                    pending.extend(item)
                elif isinstance(item, str) and token in item:
                    fail("secret_echo", "The API response contains the wallet credential and was withheld.")
        return page, collected
    finally:
        connection.close()


def run(message):
    """Execute a bounded redirect/page chain and report incomplete pagination explicitly."""
    config = configuration(message["config"])
    request = message["request"]
    token = secret_value(message["token"]) if config["auth_mode"] != "none" else ""
    deadline = time.monotonic() + config["timeout_sec"]
    url = destination(config, request["url"])
    pages, redirects, seen, total = [], 0, set(), 0
    while True:
        if url in seen:
            fail("pagination", "Redirect or pagination loop detected.")
        seen.add(url)
        page, headers = call(config, request, token, url, config["max_response_bytes"] - total, deadline)
        total += page["body_bytes"]
        if page["status"] in {301, 302, 303, 307, 308} and config["follow_redirects"] and request["method"] in {"GET", "HEAD"}:
            if redirects >= 2 or not headers.get("location"):
                fail("redirect", "Redirect limit reached or Location is missing.")
            url = destination(config, headers["location"], current=url)
            redirects += 1
            continue
        pages.append(page)
        successful = 200 <= page["status"] < 300
        link = next_link(headers.get("link")) if successful and request["method"] == "GET" else None
        if link and config["max_pages"] > 1 and len(pages) < config["max_pages"]:
            url = destination(config, link, current=url)
            continue
        result = {"response": {"id": request["id"], "method": request["method"], "pages": pages,
            "http_ok": all(200 <= item["status"] < 300 for item in pages),
            "complete": link is None, "next_available": link is not None,
            "pages_limit_reached": link is not None and len(pages) >= config["max_pages"],
            "body_bytes": total, "redirects_followed": redirects, "retry_performed": False}}
        if not successful:
            result["error"] = HttpError("http_status", "The API returned a non-success HTTP status.",
                                        ambiguous=request["method"] not in SAFE).envelope()
        return result


def main():
    """Credentials travel only in the private stdin pipe, never process arguments or environment."""
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    resource.setrlimit(resource.RLIMIT_AS, (402653184, 402653184))
    resource.setrlimit(resource.RLIMIT_NOFILE, (64, 64))
    message = None
    try:
        raw = sys.stdin.buffer.read(12582913)
        if len(raw) > 12582912:
            fail("input_limit", "Worker request exceeds its limit.")
        message = json.loads(raw)
        result = run(message)
    except BaseException as exc:
        uncertain = bool(isinstance(message, dict) and message.get("request", {}).get("method") not in SAFE)
        error = exc if isinstance(exc, HttpError) else HttpError("transport", "HTTP transport, TLS or response decoding failed.")
        if uncertain:
            error.ambiguous = True
        result = {"error": error.envelope()}
    sys.stdout.buffer.write(encoded(result, 33554432))
    sys.stdout.buffer.flush()


if __name__ == "__main__":
    main()
