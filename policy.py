"""Pure HTTP policy: fixed destination, exact capabilities and strict bounded values."""

from collections.abc import Mapping
import ipaddress
import json
from pathlib import Path
import re
from urllib.parse import quote, unquote, urlencode, urlsplit, urlunsplit, urljoin

DEFAULTS = {"base_url": "https://example.invalid/", "allowed_methods": ["GET", "HEAD"],
    "auth_mode": "none", "secret_ref": "", "auth_header": "X-API-Key", "allow_private_network": False,
    "allow_insecure_http": False, "ca_file": "", "timeout_sec": 15, "max_request_bytes": 262144,
    "max_response_bytes": 1048576, "max_pages": 1, "follow_redirects": False}
METHODS = {"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"}
FORBIDDEN_HEADERS = {"host", "content-length", "transfer-encoding", "connection", "proxy-authorization",
    "cookie", "set-cookie", "accept-encoding", "content-type", "authorization", "upgrade", "te", "trailer"}
PRIVATE = tuple(ipaddress.ip_network(x) for x in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "fc00::/7"))
TOKEN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}\Z")


class HttpError(ValueError):
    """Content-free diagnostic with a stable machine-readable code."""

    def __init__(self, code, message, *, ambiguous=False):
        super().__init__(message)
        self.code, self.ambiguous = code, ambiguous

    def envelope(self):
        """Never include raw exception, response or credential content."""
        return {"code": self.code, "message": str(self), "ambiguous": self.ambiguous, "retry_performed": False}


def fail(code, message):
    """Raise policy failures before any socket is opened."""
    raise HttpError(code, message)


def thaw(value):
    """Normalize immutable preparation snapshots without contacting a service."""
    if isinstance(value, Mapping):
        return {k: thaw(v) for k, v in value.items()}
    if isinstance(value, (tuple, list)):
        return [thaw(v) for v in value]
    return value


def encoded(value, limit):
    """Validate finite JSON and impose structure bounds before serialization."""
    pending, count = [(value, 0)], 0
    while pending:
        item, depth = pending.pop()
        count += 1
        if depth > 24 or count > 50000:
            fail("json_limit", "JSON exceeds depth or element limits.")
        if isinstance(item, dict):
            if any(not isinstance(key, str) for key in item):
                fail("json", "JSON object keys must be strings.")
            pending.extend((child, depth + 1) for child in item.values())
        elif isinstance(item, list):
            pending.extend((child, depth + 1) for child in item)
        elif item is not None and type(item) not in (str, int, float, bool):
            fail("json", "A strict JSON value is required.")
    try:
        result = json.dumps(value, ensure_ascii=False, allow_nan=False, separators=(",", ":"))
        data = result.encode("utf-8")
    except (ValueError, TypeError, UnicodeError, RecursionError):
        fail("json", "Finite UTF-8 JSON is required.")
    if len(data) > limit:
        fail("json_limit", "JSON exceeds the byte limit.")
    return data


def decode(value, limit):
    """Strict incoming JSON, including rejection of ambiguous duplicate properties."""
    if isinstance(value, str):
        try:
            raw = value.encode("utf-8")
        except UnicodeError:
            fail("json", "UTF-8 JSON is required.")
        if len(raw) > limit:
            fail("json_limit", "Input exceeds its byte limit.")
        def pairs(items):
            result = {}
            for key, child in items:
                if key in result:
                    fail("json", "Duplicate JSON property.")
                result[key] = child
            return result
        try:
            value = json.loads(value, object_pairs_hook=pairs)
        except (ValueError, RecursionError):
            fail("json", "A strict JSON object is required.")
    encoded(value, limit)
    if not isinstance(value, dict):
        fail("json", "A JSON object is required.")
    return value


def path_value(value):
    """Reject path/query confusion and ambiguous traversal before canonical quoting."""
    if not isinstance(value, str) or len(value) > 4096 or any(ord(c) < 32 or ord(c) == 127 for c in value):
        fail("path", "Invalid request path.")
    try:
        decoded = unquote(value, encoding="utf-8", errors="strict")
    except UnicodeError:
        fail("path", "Invalid UTF-8 path.")
    if any(c in decoded for c in ("%", "\\", "?", "#")) or "//" in decoded or any(x in {".", ".."} for x in decoded.split("/")):
        fail("path", "Path traversal, duplicate escaping or query delimiters are forbidden.")
    if any(ord(c) < 32 or ord(c) == 127 for c in decoded):
        fail("path", "Control characters are forbidden in paths.")
    return quote(decoded, safe="/-._~")


def origin(value):
    """Return canonical scheme/host/port with no credentials or authority ambiguity."""
    if not isinstance(value, str) or not 1 <= len(value) <= 8192 or any(ord(c) < 33 or ord(c) > 126 for c in value) or "\\" in value:
        fail("url", "Use an ASCII HTTP(S) URL without whitespace or credentials.")
    try:
        parsed = urlsplit(value)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname or parsed.username is not None or parsed.password is not None or parsed.fragment:
            raise ValueError()
        host = parsed.hostname.lower()
        if "%" in host or host.endswith("."):
            raise ValueError()
        try:
            ipaddress.ip_address(host)
        except ValueError:
            if len(host) > 253 or any(not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label) for label in host.split(".")):
                raise ValueError()
        port = parsed.port if parsed.port is not None else (443 if parsed.scheme == "https" else 80)
        if not 1 <= port <= 65535:
            raise ValueError()
        return parsed, (parsed.scheme, host, port)
    except ValueError:
        fail("url", "Invalid HTTP(S) origin, host or port.")


def configuration(raw):
    """Pure configuration validation; no DNS, CA-file or wallet access during preparation."""
    if not isinstance(raw, Mapping) or set(raw) - set(DEFAULTS) - {"execution", "runtime_path", "runtime_path_label"}:
        fail("config", "Unknown HTTP setting.")
    config = {**DEFAULTS, **{key: thaw(value) for key, value in raw.items() if key in DEFAULTS}}
    for key in ("allow_private_network", "allow_insecure_http", "follow_redirects"):
        if type(config[key]) is not bool:
            fail("config", key + " must be boolean.")
    parsed, target = origin(config["base_url"])
    if parsed.query or "?" in config["base_url"] or "#" in config["base_url"]:
        fail("config", "The API root must not contain a query or fragment.")
    path_value(parsed.path)
    if target[0] == "http" and not config["allow_insecure_http"]:
        fail("config", "Plain HTTP requires explicit opt-in.")
    methods = config["allowed_methods"]
    if not isinstance(methods, list) or not 1 <= len(methods) <= len(METHODS) or any(not isinstance(x, str) or x not in METHODS for x in methods) or len(set(methods)) != len(methods):
        fail("config", "allowed_methods must contain unique supported uppercase HTTP methods.")
    if not isinstance(config["auth_mode"], str) or config["auth_mode"] not in {"none", "bearer", "header"}:
        fail("config", "Choose none, bearer or header authentication.")
    ref = config["secret_ref"]
    if not isinstance(ref, str) or len(ref) > 200 or (ref and not re.fullmatch(r"(?:secret://workspace/)?[A-Za-z0-9_.-]+", ref)):
        fail("config", "Use a workspace wallet secret reference, not a credential.")
    if config["auth_mode"] != "none" and (not ref or target[0] != "https"):
        fail("config", "Authentication requires a wallet reference and verified HTTPS.")
    header = config["auth_header"]
    if not isinstance(header, str) or not re.fullmatch(r"[A-Za-z0-9-]{1,64}", header) or header.lower() in FORBIDDEN_HEADERS or header.lower().startswith(("proxy-", "sec-", "x-forwarded-")):
        fail("config", "The custom authentication header is not allowed.")
    for key, low, high in (("timeout_sec", 1, 120), ("max_request_bytes", 1024, 1048576),
                          ("max_response_bytes", 1024, 4194304), ("max_pages", 1, 8)):
        if type(config[key]) is not int or not low <= config[key] <= high:
            fail("config", key + " is outside its integer limits.")
    ca = config["ca_file"]
    if not isinstance(ca, str) or len(ca) > 4096 or "\x00" in ca or (ca and not Path(ca).is_absolute()):
        fail("config", "ca_file must be empty or an absolute PEM file path.")
    return config


def destination(config, value, *, relative=False, current=None):
    """Every request, redirect and next link stays within the exact configured root."""
    base, base_origin = origin(config["base_url"])
    base_path = path_value(base.path).rstrip("/")
    if relative:
        subpath = path_value(value)
        joined = base_path + "/" + subpath.lstrip("/")
        candidate = urlunsplit((base.scheme, base.netloc, joined, "", ""))
    else:
        candidate = urljoin(current or config["base_url"], value)
    parsed, dest_origin = origin(candidate)
    path = path_value(parsed.path)
    if dest_origin != base_origin or not (path == base_path or path.startswith(base_path + "/")):
        fail("destination", "The destination escapes the configured API origin or path root.")
    if any(ord(c) < 33 or ord(c) > 126 for c in parsed.query) or len(parsed.query) > 4096:
        fail("query", "Invalid or oversized query.")
    return urlunsplit((parsed.scheme, parsed.netloc, path, parsed.query, ""))


def request(value, config):
    """Inputs select a scoped path, method, scalar query and JSON or text body only."""
    value = decode(value, config["max_request_bytes"])
    if set(value) - {"id", "path", "method", "query", "body", "text"}:
        fail("request", "Request accepts id, path, method, query and either body or text.")
    method = value.get("method", "GET")
    if not isinstance(method, str) or method not in config["allowed_methods"]:
        fail("method", "The HTTP method is not permitted by this block.")
    ident = value.get("id", "")
    if not isinstance(ident, str) or ident and not TOKEN.fullmatch(ident):
        fail("request", "Invalid request identifier.")
    url = destination(config, value.get("path", ""), relative=True)
    query = value.get("query", {})
    if not isinstance(query, dict) or len(query) > 100:
        fail("query", "query must be an object with at most 100 scalar entries.")
    for key, val in query.items():
        if not isinstance(key, str) or not 1 <= len(key) <= 128 or type(val) not in (str, int, float, bool):
            fail("query", "Query names and values must be bounded strings or finite scalars.")
        if len(str(val)) > 2048:
            fail("query", "A query value exceeds its size limit.")
    encoded(query, 4096)
    if query:
        url += "?" + urlencode(query)
    if len(url) > 8192:
        fail("url", "Request URL exceeds its limit.")
    if "body" in value and "text" in value:
        fail("body", "Use either JSON body or text, not both.")
    content_type, body = None, None
    if "body" in value:
        body = encoded(value["body"], config["max_request_bytes"]).decode("utf-8")
        content_type = "application/json"
    elif "text" in value:
        if not isinstance(value["text"], str):
            fail("body", "text must be a string.")
        body = value["text"]
        content_type = "text/plain; charset=utf-8"
    if method in {"GET", "HEAD"} and body is not None:
        fail("body", "GET and HEAD requests cannot carry a body.")
    return {"id": ident, "url": url, "method": method, "body": body, "content_type": content_type}


def address_allowed(value, config):
    """Block non-public networks by default; private opt-in never includes metadata/link-local."""
    try:
        address = ipaddress.ip_address(value.split("%")[0])
        address = getattr(address, "ipv4_mapped", None) or address
    except ValueError:
        fail("dns", "DNS returned an invalid address.")
    if address.is_multicast or address.is_link_local or address.is_unspecified:
        return False
    if address.is_global and not address.is_reserved:
        return True
    return config["allow_private_network"] and (address.is_loopback or any(address.version == net.version and address in net for net in PRIVATE))


def secret_value(value):
    """Header-safe credential from the wallet only; never accept multiline/binary secrets."""
    if not isinstance(value, str) or not 8 <= len(value) <= 8192 or any(ord(c) < 33 or ord(c) > 126 for c in value):
        fail("secret", "The wallet credential must be an 8–8192 character printable non-whitespace token.")
    return value
