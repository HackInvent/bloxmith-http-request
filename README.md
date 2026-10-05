# HTTP Request

![HTTP Request](media/cover.png)

Make controlled JSON/text API calls from a workflow. The block owns the HTTP
implementation; the framework supplies the runtime lifecycle and wallet helpers.

<!-- block-metadata:start -->
[![Block version: 0.1.0](https://img.shields.io/badge/block-0.1.0-blue)](model.json)
[![BloxSmith compatibility: 1.0.9](https://img.shields.io/badge/BloxSmith-1.0.9-brightgreen)](compatibility.json)
[![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue)](LICENSE)

Verified BloxSmith versions: **1.0.9** (bundled-block tests; see [test evidence](compatibility.json)).
<!-- block-metadata:end -->

## Setup

Set `base_url` to one authorized API root, for example
`https://api.example.invalid/v1/`. Requests, followed redirects and fetched next
pages must stay on that exact scheme/host/port and path prefix. No URL, proxy,
authentication header or TLS override is accepted from an input.

Only `GET` and `HEAD` are enabled by default. Add `POST`, `PUT`, `PATCH`,
`DELETE` or `OPTIONS` deliberately to `allowed_methods` when the workflow is
authorized to perform those operations. This is a capability boundary, not a
human approval gate: each received authorized request executes immediately,
including in One Shot. Put a separate review step upstream when required.

Choose authentication `none`, `bearer` or a custom `header`. Credentials must
come from `secret_ref` in the wallet (bare workspace name or
`secret://workspace/name`); they are never configured directly. Header mode uses
`auth_header` (default `X-API-Key`). Routing/proxy/cookie headers are forbidden.
A locked wallet produces an explicit error, with no plaintext fallback.

Authentication requires **HTTPS with certificate/hostname verification**.
An optional `ca_file` selects an existing PEM trust file for a private service.
There is no switch to disable TLS verification. Credentials travel to the owned
worker only through stdin, never process arguments, environment or temporary files.

## Ports and request

| Port | Direction | Value |
| --- | --- | --- |
| `request` | Input | Strict JSON object or JSON text |
| `response` | Output | Complete accepted page bodies and bounded HTTP metadata |
| `error` | Output | Content-free `code`, `message`, `ambiguous`, `retry_performed:false` |

```json
{
  "id": "lookup-42",
  "method": "GET",
  "path": "items",
  "query": {"limit": 10, "category": "tools"}
}
```

Paths are relative to the configured root; a leading slash does **not** escape
that root. Query values are finite scalar strings/numbers/booleans. Do not put
authentication secrets in a path, query or body. Unsupported fields are rejected.

For JSON writes, send `body`; for UTF-8 plain text, send `text`, never both:

```json
{"method":"POST","path":"drafts","body":{"title":"Reviewed draft"}}
```

GET/HEAD bodies, raw input headers, multipart upload, binary download, streaming
and cookie sessions are not implemented. Response data is untrusted content;
render returned HTML text only through an appropriately restricted viewer.

## Response and failures

`response` contains `id`, `method`, `pages`, `http_ok`, `complete`,
`next_available`, `pages_limit_reached`, cumulative `body_bytes`,
`redirects_followed` and `retry_performed:false`.
Each page has HTTP `status`, allowlisted `headers`, `content_type`, decoded
`body` and `body_bytes`. JSON is parsed strictly; text must be UTF-8.
Only JSON/`+json` and `text/*` bodies are accepted. Empty bodies become null.
Compression is not decoded: the block requests identity encoding and refuses
compressed responses. Oversized, malformed and truncated bodies are not success.

A complete non-2xx response emits both `response` and `error`. Transport,
policy, parsing or size failure emits **error only**, never an invented empty
success or partly downloaded body. All expected failures are graph diagnostics:
the task completes, and downstream logic must inspect the error port/`http_ok`.
Configuration errors can fail Run preparation before any request is made.

`ambiguous:true` means a mutation may already have been applied remotely; do not
retry blindly. Cancellation/timeout can stop local work but cannot undo a remote
side effect. The block never performs an automatic retry, including after 429,
5xx or a dropped connection. This follows the distinction between safe/idempotent
and non-idempotent operations in [HTTP semantics](https://www.rfc-editor.org/rfc/rfc9110.html).

The request ID is correlation data, **not** a server idempotency key or a durable
deduplication ledger. Re-sending an input is a new request.

## Pagination and redirects

`max_pages:1` disables automatic pagination. Increasing it up to 8 follows a
constrained standard [Link rel=next](https://www.rfc-editor.org/rfc/rfc8288.html)
on successful GET responses only. Ambiguous/unsupported Link syntax is reported;
JSON-specific cursors and anchored next links are not interpreted. A remaining
next link sets `complete:false` and `next_available:true`, without pretending
the whole collection was read. Page limits never cause an unbounded catch-up.

`follow_redirects` is off by default. When enabled, GET/HEAD can follow at most
two 301/302/303/307/308 responses within the same configured origin/path root.
Writes are never replayed to a redirect destination. Loops are refused.

## Network and resource policy

All DNS answers are checked before connecting. Connections use the checked numeric
address, while HTTPS still verifies the configured hostname. Private/loopback
destinations are denied unless `allow_private_network` is explicitly enabled.
Link-local, unspecified, multicast and non-public non-LAN destinations remain
denied. This is not a complete organization-wide egress firewall: use network
policy as well when exposing the workflow to untrusted request authors.

Plain HTTP requires `allow_insecure_http` and cannot carry wallet authentication.
Proxy environment variables are not used. The subprocess receives a minimal
environment; system CA trust or the explicit CA file controls HTTPS trust.

A short-lived owned Python process contains DNS and network I/O, so the parent
can terminate it even during a blocked resolver call. The shared network deadline
is 15 seconds by default (1–120 configurable), including connection, redirects
and pages. Wallet service resolution occurs beforehand under the framework's
own contract. Stop/inhibition is checked every 100 ms; the child is terminated
and reaped. No server, background listener or detached thread is created.

Input JSON defaults to 256 KiB (max 1 MiB); cumulative response bodies default
to 1 MiB (max 4 MiB, including redirect bodies); each response's headers ≤32 KiB.
Depth ≤24 / 50,000 JSON values; bounded query, URL, page and redirect counts.
The POSIX worker has a 384 MiB address-space cap and core dumps disabled.

Diagnostics do not echo provider bodies, URLs, paths or credentials. A literal
wallet token found in decoded response strings/headers causes the response to be
withheld. This guard cannot recognize arbitrary transformations of a secret;
do not use credential-echoing endpoints. Sensitive business data can legitimately
be present in API responses and requires the workflow's own access/retention policy.

## Verification

Tests use local HTTP/HTTPS fixtures, never real external APIs or user wallet
credentials. They cover destination/path policy, DNS pinning, TLS trust, credential
echo refusal, limits, pagination, redirects, timeouts, cancellation, both runtimes,
managed/linked packages and responsive translated forms.

Requires Python 3.10+ on POSIX/Linux with TLS support and an appropriate CA trust
store. Licensed under Apache-2.0.

Wallet tokens must contain 8–8,192 printable non-whitespace ASCII characters.
Binary, multiline, Basic/OAuth negotiation and mutual-TLS client credentials are
not supported by this initial adapter.
