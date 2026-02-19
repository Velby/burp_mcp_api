#!/usr/bin/env python3
"""
burp_mcp.py — MCP server that exposes Burp REST Bridge as native Claude tools.

Setup:
    pip install fastmcp
    claude mcp add burp -- python3 /path/to/burp_mcp.py
"""

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
        "Use burp_search to find requests, burp_get_item to read full content, "
        "and burp_repeater_latest when the user says 'check what I just sent'."
    ),
)

_client = BurpClient()

# Common static file extensions to exclude by default — saves context
_DEFAULT_EXT_EXCLUDE = "js,css,png,gif,ico,woff,woff2,ttf,eot,svg,map,jpg,jpeg,webp,mp4,mp3,pdf"


def _safe(fn):
    """Wrap a client call so a connection error returns a readable string."""
    try:
        return fn()
    except RuntimeError as e:
        return {"error": str(e)}


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
) -> list:
    """
    Search Burp proxy/repeater history. Returns id, tool, timestamp, url, method, status_code.
    Use burp_get_item(id) to fetch full request+response for any result.

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
    """
    return _safe(lambda: _client.history(
        host=host, method=method, status=status,
        search=search, search_in=search_in, tool=tool,
        ext_exclude=ext_exclude if ext_exclude else None,
        mime=mime, order=order,
        limit=limit, offset=offset,
        mcp_only=mcp_only,
    ))


@mcp.tool()
def burp_get_item(item_id: int, max_body: int = 2000) -> dict:
    """
    Get the full decoded request and response for a single captured traffic item.

    Response body is truncated to max_body chars by default (headers always complete).
    Use max_body=0 for the full response body (may be large).

    Returns: id, tool, url, method, status_code, timestamp, request_length,
             response_length, request_text, response_text
    """
    return _safe(lambda: _client.get(item_id, max_body=max_body))


@mcp.tool()
def burp_repeater_latest(max_body: int = 3000) -> dict:
    """
    Get the most recent request sent from Burp Repeater, with full decoded content.

    Use this when the user says "look at what I just sent", "check my last Repeater request",
    or anything implying they recently sent something manually in Burp.

    Response body truncated to max_body chars (use 0 for unlimited).
    """
    return _safe(lambda: _client.repeater_latest(max_body=max_body))


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

    Returns: {status_code, headers, body, url, method, item_id}
    SSL verification is disabled (standard for security testing).
    """
    return _safe(lambda: _client.repeat(
        item_id, replacements=replacements, add_headers=add_headers,
        body=body, proxy_port=proxy_port, max_response_body=max_response_body,
    ))


@mcp.tool()
def burp_request(
    method: str,
    url: str,
    headers: dict = None,
    body: str = None,
    proxy_port: int = 8080,
    max_response_body: int = 4000,
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

    Returns: {status_code, headers, body, url, method}
    """
    return _safe(lambda: _client.request(
        method, url, headers=headers, body=body,
        proxy_port=proxy_port, max_response_body=max_response_body,
    ))


@mcp.tool()
def burp_scope(url: str) -> dict:
    """
    Check if a URL is within Burp's suite-wide target scope.
    Returns {url, in_scope: true/false}.
    """
    return _safe(lambda: _client.scope(url))


if __name__ == "__main__":
    mcp.run()
