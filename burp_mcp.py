#!/usr/bin/env python3
"""
burp_mcp.py — MCP server that exposes Burp REST Bridge as native Claude tools.

Setup:
    pip install fastmcp
    claude mcp add burp -- python3 /path/to/burp_mcp.py
"""

import json
import re
import sys
import os

# Allow importing burp_client.py from the same directory regardless of cwd
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from fastmcp import FastMCP
from burp_client import BurpClient

mcp = FastMCP(
    "Burp REST Bridge",
    instructions=(
        "Tools for interacting with Burp Suite proxy history and Repeater. "
        "Call burp_health first to confirm the extension is running. "
        "Use burp_search to find requests, burp_get_item (or burp_get_items for batch) "
        "to read full structured content, and burp_repeater_latest when the user says "
        "'check what I just sent'. "
        "For large responses, use dump_response_body=True to write to /tmp and process "
        "with bash tools (grep, jq) instead of reading inline."
    ),
)

_client = BurpClient()

# Common static file extensions to exclude by default — saves context
_DEFAULT_EXT_EXCLUDE = "js,css,png,gif,ico,woff,woff2,ttf,eot,svg,map,jpg,jpeg,webp,mp4,mp3,pdf"

# Browser-injected headers that are rarely useful for security analysis
_BORING_REQUEST_HEADERS = {
    "user-agent", "accept-encoding", "accept-language",
    "sec-fetch-dest", "sec-fetch-mode", "sec-fetch-site", "sec-fetch-user",
    "te", "connection", "pragma", "upgrade-insecure-requests",
}

# Path normalization: replace numeric IDs and UUIDs with {id}
_RE_NUMERIC_SEGMENT = re.compile(r'/\d+(?=/|$)')
_RE_UUID_SEGMENT = re.compile(
    r'/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}(?=/|$)',
    re.IGNORECASE,
)


def _normalize_path(path: str) -> str:
    """Strip query string and normalize dynamic path segments to {id}."""
    path = path.split("?")[0]
    path = _RE_NUMERIC_SEGMENT.sub('/{id}', path)
    path = _RE_UUID_SEGMENT.sub('/{id}', path)
    return path


def _safe(fn):
    """Wrap a client call so a connection error returns a readable string."""
    try:
        return fn()
    except RuntimeError as e:
        return {"error": str(e)}


# ── HTTP parsing helpers ──────────────────────────────────────────────────────

def _split_headers_body(raw_text: str) -> tuple[str, str]:
    """Split raw HTTP text into (header_section, body)."""
    for sep in ("\r\n\r\n", "\n\n"):
        if sep in raw_text:
            h, b = raw_text.split(sep, 1)
            return h, b
    return raw_text, ""


def _parse_header_lines(header_section: str) -> tuple[str, dict]:
    """Return (first_line, {header: value}) from a raw HTTP header section."""
    lines = header_section.replace("\r\n", "\n").split("\n")
    first = lines[0] if lines else ""
    headers = {}
    for line in lines[1:]:
        if ":" in line:
            k, _, v = line.partition(":")
            headers[k.strip()] = v.strip()
    return first, headers


def _try_parse_json(text: str):
    """Return parsed JSON object, or original string if not valid JSON."""
    try:
        return json.loads(text)
    except (json.JSONDecodeError, ValueError):
        return text


def _structured_request(request_text: str, url: str) -> dict:
    """Parse raw HTTP request text into a structured dict."""
    if not request_text:
        return {}
    header_part, body = _split_headers_body(request_text)
    first_line, all_headers = _parse_header_lines(header_part)

    parts = first_line.split(" ")
    method = parts[0] if parts else ""

    # Filter browser boilerplate, keep security-relevant headers
    headers = {k: v for k, v in all_headers.items()
               if k.lower() not in _BORING_REQUEST_HEADERS}

    ct = all_headers.get("Content-Type", "").lower()
    body = body.strip()
    # Only try JSON parse if body is not truncated and content-type matches
    if "application/json" in ct and body and not body.endswith("]"):
        parsed_body = _try_parse_json(body)
    else:
        parsed_body = body or None

    result = {"method": method, "url": url, "headers": headers}
    if parsed_body is not None:
        result["body"] = parsed_body
    return result


def _structured_response(response_text: str) -> dict:
    """Parse raw HTTP response text into a structured dict."""
    if not response_text:
        return {}
    header_part, body = _split_headers_body(response_text)
    first_line, headers = _parse_header_lines(header_part)

    parts = first_line.split(" ", 2)
    try:
        status = int(parts[1]) if len(parts) > 1 else 0
    except ValueError:
        status = 0

    ct = headers.get("Content-Type", "").lower()
    body = body.strip()
    # Only try JSON parse if body is not truncated and content-type matches
    if "application/json" in ct and body and not body.endswith("]"):
        parsed_body = _try_parse_json(body)
    else:
        parsed_body = body or None

    result = {"status": status, "headers": headers}
    if parsed_body is not None:
        result["body"] = parsed_body
    return result


def _to_structured(item: dict) -> dict:
    """
    Convert a raw history item (with request_text/response_text) to a
    structured format with parsed request/response objects.
    Mutates and returns the item.
    """
    if not isinstance(item, dict) or "error" in item:
        return item
    request_text = item.pop("request_text", "")
    response_text = item.pop("response_text", "")
    url = item.get("url", "")
    item["request"] = _structured_request(request_text, url)
    item["response"] = _structured_response(response_text)
    return item


def _extract_request_body(request_text: str) -> str:
    """Extract body portion from raw HTTP request text."""
    for sep in ("\r\n\r\n", "\n\n"):
        if sep in request_text:
            return request_text.split(sep, 1)[1]
    return ""


def _centered_snippet(text: str, needle: str, context: int = 200) -> str:
    """Return a snippet of text centered around the first match of needle."""
    pos = text.lower().find(needle.lower())
    if pos < 0:
        # No match found — return start of text
        return text[:context * 2] if len(text) > context * 2 else text
    start = max(0, pos - context)
    end = min(len(text), pos + len(needle) + context)
    snippet = text[start:end]
    if start > 0:
        snippet = "…" + snippet
    if end < len(text):
        snippet = snippet + "…"
    return snippet


def _dump_body_from_result(result: dict, path: str) -> None:
    """Write the 'body' field of a repeat/request result to a file, mutate result in place."""
    body = result.get("body", "")
    with open(path, "w", encoding="utf-8", errors="replace") as f:
        f.write(body)
    result["body"] = f"[response body written to {path} — {len(body)} chars]"


def _json_extract(obj, path: str):
    """Traverse a parsed JSON object using dot-notation path. Supports array indices."""
    for part in path.split("."):
        if obj is None:
            return None
        if isinstance(obj, dict):
            obj = obj.get(part)
        elif isinstance(obj, list):
            try:
                obj = obj[int(part)]
            except (ValueError, IndexError):
                return None
        else:
            return None
    return obj


def _dump_response_body(item: dict, item_id: int) -> str:
    """Write response body to /tmp, replace response_text with notice + preview, return path."""
    rt = item.get("response_text", "")
    body = rt
    headers_part = ""
    for sep in ("\r\n\r\n", "\n\n"):
        if sep in rt:
            headers_part, body = rt.split(sep, 1)
            break
    path = f"/tmp/burp_response_{item_id}.txt"
    with open(path, "w", encoding="utf-8", errors="replace") as f:
        f.write(body)
    preview = body[:200]
    notice = (
        f"[response body written to {path} — {len(body)} chars; use bash grep/jq to process]\n"
        f"[preview: {preview}]"
    )
    if "application/json" in headers_part.lower():
        notice += "\n[tip: use max_body=0 to get inline parsed JSON, or json_path=\"key\" to extract a sub-object]"
    item["response_text"] = (headers_part + "\r\n\r\n" + notice) if headers_part else notice
    return path


# ── MCP tools ─────────────────────────────────────────────────────────────────

@mcp.tool()
def burp_health() -> dict:
    """
    Check if the Burp REST Bridge extension is running.
    Returns {status, count, port}. Call this first to confirm Burp is available.
    """
    return _safe(_client.health)


@mcp.tool()
def burp_hosts() -> list:
    """
    List all unique hostnames seen in captured Burp traffic, sorted alphabetically.
    Use this to understand what targets are in scope before searching.
    """
    return _safe(_client.hosts)


@mcp.tool()
def burp_search(
    host: str = None,
    method: str = None,
    status: str = None,
    search: str = None,
    search_in: str = None,
    tool: str = None,
    ext_exclude: str = _DEFAULT_EXT_EXCLUDE,
    mime: str = None,
    order: str = None,
    limit: int = 20,
    offset: int = 0,
    mcp_only: bool = False,
    include_request_body: bool = False,
    include_response_body: bool = False,
) -> list:
    """
    Search Burp proxy/repeater history. Returns id, tool, timestamp, url, method, status_code.
    Use burp_get_item(id) or burp_get_items([ids]) to fetch full structured content.

    Body fields are never included by default. They appear only when explicitly requested
    or when search_in targets a body part — in which case inclusion is automatic so you
    can see what matched. When search is also set, the body field is a ±200 char snippet
    centered on the match; otherwise it is the first 500 chars.

    Parameters:
        host:        Hostname substring filter, e.g. "api.example.com"
        method:      Exact HTTP method: GET, POST, PUT, DELETE, ...
        status:      Status prefix: "200", "4" (all 4xx), "401"
        search:      Case-insensitive text to search for
        search_in:   Comma-separated parts to search within:
                     request, request_headers, request_body,
                     response, response_headers, response_body
                     (default: search everywhere)
        tool:        PROXY | REPEATER | SCANNER | INTRUDER | EXTENSION
        ext_exclude: Comma-separated URL extensions to exclude (default: common static files)
                     Pass "" to include everything including js/css/images
        mime:        Filter by response Content-Type substring: "json", "html", "xml"
        order:       "asc" = oldest first (useful for finding first occurrence); default newest first
        limit:       Max results (default 20)
        offset:      Pagination offset
        mcp_only:    If True, only return requests sent via MCP tools (burp_repeat/burp_request).
                     These items are highlighted cyan in Burp's UI and carry an mcp_tag field.
        include_request_body:  Add request_body to each result (off by default).
                     Auto-enabled when search_in contains "request_body" or "request".
        include_response_body: Add response_body to each result (off by default).
                     Auto-enabled when search_in contains "response_body" or "response".
    """
    # Determine which body sides to include based on search_in and explicit flags
    search_parts = {p.strip() for p in search_in.split(",")} if search_in else set()
    want_req_body = include_request_body or "request_body" in search_parts or "request" in search_parts
    want_resp_body = include_response_body or "response_body" in search_parts or "response" in search_parts

    if not (want_req_body or want_resp_body):
        return _safe(lambda: _client.history(
            host=host, method=method, status=status,
            search=search, search_in=search_in, tool=tool,
            ext_exclude=ext_exclude if ext_exclude else None,
            mime=mime, order=order,
            limit=limit, offset=offset,
            mcp_only=mcp_only,
        ))

    # Build fields list for only the sides we need
    extra_fields = []
    if want_req_body:
        extra_fields.append("request_text")
    if want_resp_body:
        extra_fields.append("response_text")
    fields = "id,tool,timestamp,url,method,status_code,mcp_tag," + ",".join(extra_fields)

    result = _safe(lambda: _client.history(
        host=host, method=method, status=status,
        search=search, search_in=search_in, tool=tool,
        ext_exclude=ext_exclude if ext_exclude else None,
        mime=mime, order=order,
        limit=limit, offset=offset,
        mcp_only=mcp_only,
        fields=fields,
        max_body=0,  # fetch full body so we can center the snippet on the match
    ))

    if isinstance(result, list):
        for item in result:
            if want_req_body:
                rt = item.pop("request_text", None)
                if rt is not None:
                    body = _extract_request_body(rt)
                    item["request_body"] = _centered_snippet(body, search) if (search and body) else (body[:500] if len(body) > 500 else body)
            if want_resp_body:
                resp_text = item.pop("response_text", None)
                if resp_text is not None:
                    _, body = _split_headers_body(resp_text)
                    body = body.strip()
                    item["response_body"] = _centered_snippet(body, search) if (search and body) else (body[:500] if len(body) > 500 else body)
    return result


@mcp.tool()
def burp_get_items(
    item_ids: list,
    max_body: int = 2000,
    dump_response_body: bool = False,
    json_path: str = None,
) -> list:
    """
    Get full structured request and response for one or more captured traffic items.
    Pass a single-element list for one item: burp_get_items([42]).

    Returns a structured object per item with:
      request: {method, url, headers (dict, browser noise filtered), body (JSON-parsed if applicable)}
      response: {status, headers (dict), body (JSON-parsed if applicable)}

    Response body handling (applied per item):
    - Default (max_body=2000): if body exceeds max_body chars, it is auto-dumped to
      /tmp/burp_response_{id}.txt and replaced with the file path + 200-char preview.
    - Set max_body=0 to get full bodies inline (may be large — use sparingly).
    - Set dump_response_body=True to always dump to file regardless of size.

    json_path: dot-notation path to extract from a JSON response body, e.g. "data.users"
               or "results.0.token". Applied to every item in the list. When set and the
               response is JSON, auto-dump is bypassed and only the matched sub-object is
               returned in response.body. Array indices supported: "items.3" = 4th element.
               Ideal for large JSON responses where you only need one key or nested object.

    Parameters:
        item_ids:           List of IDs from burp_search results (recommended: up to 20)
        max_body:           Truncate response body to N chars per item (0 = unlimited)
        dump_response_body: Always dump response bodies to /tmp regardless of size
        json_path:          Extract a sub-object from each JSON response body
    """
    results = []
    for item_id in item_ids:
        item = _safe(lambda iid=item_id: _client.get(iid, max_body=0))
        if not isinstance(item, dict) or "error" in item:
            results.append(item)
            continue

        headers_part, resp_body = _split_headers_body(item.get("response_text", ""))
        is_json_ct = "application/json" in headers_part.lower()
        should_dump = dump_response_body or (max_body > 0 and len(resp_body) > max_body)

        # json_path bypasses dump when response is JSON — we parse and extract instead
        if should_dump and not (json_path and is_json_ct):
            _dump_response_body(item, item_id)

        result = _to_structured(item)

        if json_path and isinstance(result, dict):
            body = result.get("response", {}).get("body")
            if isinstance(body, (dict, list)):
                result["response"]["body"] = _json_extract(body, json_path)
            else:
                result["response"]["json_path_error"] = (
                    "response body is not JSON — json_path requires application/json content-type"
                    if not is_json_ct else
                    "response body could not be parsed as JSON"
                )

        results.append(result)
    return results


@mcp.tool()
def burp_repeater_latest(max_body: int = 3000) -> dict:
    """
    Get the most recent request sent from Burp Repeater, with full structured content.

    Use this when the user says "look at what I just sent", "check my last Repeater request",
    or anything implying they recently sent something manually in Burp.

    Response body truncated to max_body chars (use 0 for unlimited).
    Returns same structured format as burp_get_item.
    """
    item = _safe(lambda: _client.repeater_latest(max_body=max_body))
    return _to_structured(item)


@mcp.tool()
def burp_send_to_repeater(history_id: int, tab_name: str = None) -> dict:
    """
    Send a captured request to Burp Repeater for manual testing.

    Parameters:
        history_id: ID from burp_search results
        tab_name:   Optional label for the Repeater tab
    """
    return _safe(lambda: _client.send_to_repeater(history_id=history_id, tab_name=tab_name))


@mcp.tool()
def burp_repeat(
    item_id: int,
    replacements: dict = None,
    add_headers: dict = None,
    body: str = None,
    proxy_port: int = 8080,
    max_response_body: int = 4000,
    dump_response_body: bool = False,
) -> dict:
    """
    Fetch a captured request by ID, optionally modify it, and resend it through Burp's proxy.
    The repeated request appears in Burp's proxy history alongside normal traffic.

    Parameters:
        item_id:          ID from burp_search results
        replacements:     String substitutions applied to the raw request before sending.
                          Use this to swap tokens, params, or any text, e.g.:
                            {"Bearer old_token": "Bearer new_token"}
                            {"role=user": "role=admin"}
        add_headers:      Headers to add or override, e.g. {"X-Forwarded-For": "127.0.0.1"}
        body:             Replace the request body entirely (useful for POST/PUT)
        proxy_port:       Burp proxy listener port (default 8080)
        max_response_body: Truncate response body to N chars (0 = unlimited)
        dump_response_body: Write the full response body to /tmp/burp_response_{item_id}.txt
                          instead of returning it inline. max_response_body is ignored.

    Returns: {status_code, headers, body, url, method, item_id}
    SSL verification is disabled (standard for security testing).
    """
    result = _safe(lambda: _client.repeat(
        item_id, replacements=replacements, add_headers=add_headers,
        body=body, proxy_port=proxy_port,
        max_response_body=0 if dump_response_body else max_response_body,
    ))
    if dump_response_body and isinstance(result, dict) and "error" not in result:
        _dump_body_from_result(result, f"/tmp/burp_response_{item_id}.txt")
    return result


@mcp.tool()
def burp_request(
    method: str,
    url: str,
    headers: dict = None,
    body: str = None,
    proxy_port: int = 8080,
    max_response_body: int = 4000,
    dump_response_body: bool = False,
) -> dict:
    """
    Send a custom HTTP request through Burp's proxy.
    The request appears in Burp's proxy history. SSL verification is disabled.

    Parameters:
        method:  HTTP method: GET, POST, PUT, DELETE, PATCH, ...
        url:     Full URL including scheme, e.g. "https://api.example.com/users"
        headers: Request headers dict, e.g. {"Authorization": "Bearer token"}
        body:    Request body string (for POST/PUT/PATCH)
        proxy_port: Burp proxy listener port (default 8080)
        max_response_body: Truncate response body to N chars (0 = unlimited)
        dump_response_body: Write the full response body to /tmp/burp_response_latest.txt
                          instead of returning it inline. max_response_body is ignored.

    Returns: {status_code, headers, body, url, method}
    """
    result = _safe(lambda: _client.request(
        method, url, headers=headers, body=body,
        proxy_port=proxy_port,
        max_response_body=0 if dump_response_body else max_response_body,
    ))
    if dump_response_body and isinstance(result, dict) and "error" not in result:
        _dump_body_from_result(result, "/tmp/burp_response_latest.txt")
    return result


_SUMMARIZE_BATCH = 200   # items per page
_SUMMARIZE_MAX_RAW = 10_000  # absolute safety cap on raw items fetched


@mcp.tool()
def burp_summarize_host(host: str, limit: int = 500, ext_exclude: str = _DEFAULT_EXT_EXCLUDE) -> dict:
    """
    Summarize the API surface for a host from captured traffic.

    Returns:
      - endpoints: unique method × normalized-path combinations with their observed status codes.
                   Query strings are stripped; numeric and UUID path segments are replaced with {id}
                   so e.g. /files/5503495/download and /files/5503497/download → /files/{id}/download.
      - status_distribution: count of each status code seen (across sampled requests)
      - auth_schemes: authentication methods observed in requests (bearer, basic, cookie, etc.)
      - response_content_types: content types returned by the host

    Static assets (js, css, images, fonts, etc.) are excluded by default to keep the
    endpoint list focused on API/page traffic. The response notes what is hidden and
    how to include it.

    Sampling strategy: paginates through history in batches, stopping automatically once
    two consecutive pages yield no new endpoint patterns. This means high-volume repetitive
    calls (e.g. /file/{id}/download called 200 times) don't crowd out coverage of rarer
    endpoints. Auth and content-type headers are only sampled once per unique endpoint.
    limit caps unique endpoints discovered, not raw items fetched.

    Parameters:
        host:        Hostname to summarize (substring match, e.g. "api.example.com")
        limit:       Max unique normalized endpoints to discover (default 500).
                     Sampling stops earlier if history is exhausted or no new endpoints
                     appear across two consecutive pages.
        ext_exclude: Comma-separated file extensions to exclude (default: js,css,images,fonts,...).
                     Pass ext_exclude="" to include all traffic including static assets.
                     Pass ext_exclude="js,css" to exclude only those types.
    """
    endpoints: dict[str, set] = {}   # "METHOD /path" → set of status codes
    status_dist: dict[str, int] = {}
    auth_schemes: set[str] = set()
    content_types: set[str] = set()

    offset = 0
    total_raw = 0
    consecutive_no_new = 0

    while len(endpoints) < limit and total_raw < _SUMMARIZE_MAX_RAW:
        batch = _safe(lambda o=offset: _client.history(
            host=host, limit=_SUMMARIZE_BATCH, offset=o,
            fields="method,path,status_code,request_headers,response_headers",
            ext_exclude=ext_exclude if ext_exclude else None,
        ))
        if not isinstance(batch, list):
            return batch  # propagate error
        if not batch:
            break

        new_this_batch = 0
        for item in batch:
            key = f"{item.get('method', '?')} {_normalize_path(item.get('path', '/'))}"
            sc = item.get("status_code", 0)
            is_new = key not in endpoints
            endpoints.setdefault(key, set()).add(sc)

            sc_str = str(sc)
            status_dist[sc_str] = status_dist.get(sc_str, 0) + 1

            if is_new:
                new_this_batch += 1
                # Sample auth/content-type headers once per unique endpoint
                req_headers = item.get("request_headers", "")
                for line in req_headers.replace("\r\n", "\n").split("\n"):
                    ll = line.lower()
                    if ll.startswith("authorization:"):
                        val = line.split(":", 1)[1].strip()
                        scheme = val.split(" ")[0].lower() if " " in val else val.lower()
                        auth_schemes.add(scheme)
                    elif ll.startswith("cookie:"):
                        auth_schemes.add("cookie")

                resp_headers = item.get("response_headers", "")
                for line in resp_headers.replace("\r\n", "\n").split("\n"):
                    if line.lower().startswith("content-type:"):
                        ct = line.split(":", 1)[1].strip().split(";")[0].strip().lower()
                        if ct:
                            content_types.add(ct)

        total_raw += len(batch)
        offset += _SUMMARIZE_BATCH

        if new_this_batch == 0:
            consecutive_no_new += 1
            if consecutive_no_new >= 2:
                break
        else:
            consecutive_no_new = 0

        if len(batch) < _SUMMARIZE_BATCH:
            break  # end of history

    note = f"found {len(endpoints)} unique endpoints from {total_raw} requests sampled"
    if len(endpoints) >= limit:
        note += f" (endpoint limit {limit} reached — raise limit to discover more)"
    if ext_exclude:
        note += f" — static assets excluded ({ext_exclude}); pass ext_exclude='' to include them"

    return {
        "host": host,
        "total_requests_sampled": total_raw,
        "note": note,
        "endpoints": [
            {"endpoint": k, "status_codes": sorted(v)}
            for k, v in sorted(endpoints.items())
        ],
        "status_distribution": {k: status_dist[k] for k in sorted(status_dist)},
        "auth_schemes": sorted(auth_schemes),
        "response_content_types": sorted(content_types),
    }


@mcp.tool()
def burp_scope(url: str) -> dict:
    """
    Check if a URL is within Burp's suite-wide target scope.
    Returns {url, in_scope: true/false}.
    """
    return _safe(lambda: _client.scope(url))


if __name__ == "__main__":
    mcp.run()
