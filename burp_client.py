#!/usr/bin/env python3
"""
burp_client.py — Python client for the Burp REST Bridge extension.

Usage (standalone):
    python3 burp_client.py health
    python3 burp_client.py hosts
    python3 burp_client.py history [--host HOST] [--method METHOD] [--status STATUS]
                                    [--search TEXT] [--search-in PARTS] [--tool TOOL]
                                    [--ext-exclude EXTS] [--mime TYPE]
                                    [--order asc|desc] [--limit N] [--offset N]
                                    [--fields FIELDS] [--max-body N]
    python3 burp_client.py get <id> [--max-body N]
    python3 burp_client.py latest            # most recent Repeater send
    python3 burp_client.py repeater <id> [--tab NAME]
    python3 burp_client.py scope <url>
    python3 burp_client.py docs              # fetch API reference

Importable:
    from burp_client import BurpClient
    b = BurpClient()
    items = b.history(host="example.com", search="password",
                      search_in="response_body", ext_exclude="js,css,png")
    latest = b.repeater_latest()
    b.send_to_repeater(latest["id"], tab_name="re-test")
"""

import argparse
import json
import sys
import urllib.request
import urllib.parse
import urllib.error
from typing import Optional

BASE_URL = "http://127.0.0.1:8090"


class BurpClient:
    def __init__(self, base_url: str = BASE_URL, timeout: int = 10):
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout

    # ── core ──────────────────────────────────────────────────────────────────

    def _get(self, path: str, params: dict = None) -> dict | list | str:
        url = self.base_url + path
        if params:
            filtered = {k: str(v) for k, v in params.items() if v is not None and v != ""}
            if filtered:
                url += "?" + urllib.parse.urlencode(filtered)
        try:
            with urllib.request.urlopen(url, timeout=self.timeout) as resp:
                body = resp.read().decode("utf-8", errors="replace")
                ct = resp.headers.get("Content-Type", "")
                if "text/plain" in ct:
                    return body
                return json.loads(body)
        except urllib.error.HTTPError as e:
            raise RuntimeError(f"HTTP {e.code}: {e.read().decode()}") from e
        except urllib.error.URLError as e:
            raise RuntimeError(
                f"Cannot connect to Burp REST Bridge at {self.base_url}. "
                "Is the extension loaded and Burp running?"
            ) from e

    def _post(self, path: str, body: dict) -> dict:
        url = self.base_url + path
        data = json.dumps(body).encode()
        req = urllib.request.Request(url, data=data,
                                     headers={"Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                return json.loads(resp.read().decode())
        except urllib.error.HTTPError as e:
            raise RuntimeError(f"HTTP {e.code}: {e.read().decode()}") from e
        except urllib.error.URLError as e:
            raise RuntimeError(
                f"Cannot connect to Burp REST Bridge at {self.base_url}."
            ) from e

    # ── public API ────────────────────────────────────────────────────────────

    def health(self) -> dict:
        """Return {"status": "ok", "count": N, "port": 8090}."""
        return self._get("/health")

    def docs(self) -> str:
        """Fetch the LLM-friendly API reference as plain text."""
        return self._get("/")

    def hosts(self) -> list[str]:
        """Return sorted list of unique hostnames seen in captured traffic."""
        return self._get("/proxy/hosts").get("hosts", [])

    def history(
        self,
        host: Optional[str] = None,
        method: Optional[str] = None,
        status: Optional[str] = None,
        search: Optional[str] = None,
        search_in: Optional[str] = None,
        tool: Optional[str] = None,
        ext_exclude: Optional[str] = None,
        mime: Optional[str] = None,
        order: Optional[str] = None,
        limit: int = 100,
        offset: int = 0,
        fields: Optional[str] = None,
        max_body: int = 0,
        mcp_only: bool = False,
    ) -> list[dict]:
        """
        Search captured traffic. Results are newest first by default.

        Args:
            host:        Substring match on hostname
            method:      Exact HTTP method: GET, POST, PUT, DELETE, ...
            status:      Prefix match: "200", "4" (all 4xx), "20" (200-209)
            search:      Case-insensitive search text
            search_in:   Limit search to parts (comma-separated):
                         request, request_headers, request_body,
                         response, response_headers, response_body
            tool:        PROXY | REPEATER | SCANNER | INTRUDER | EXTENSION
            ext_exclude: Comma-separated URL extensions to exclude, e.g. "js,css,png,gif"
            mime:        Filter by response Content-Type substring, e.g. "json", "html"
            order:       "asc" for oldest first, default newest first
            limit:       Max results (default 100)
            offset:      Pagination offset
            fields:      Comma-separated fields to include, e.g. "url,status_code,method"
                         Default: id,tool,timestamp,url,method,status_code
            max_body:    Truncate body text to N chars when fields includes *_text (0=unlimited)
            mcp_only: If True, only return requests sent by Claude via burp_repeat/burp_request
        """
        return self._get("/proxy/history", {
            "host": host, "method": method, "status": status,
            "search": search, "search_in": search_in, "tool": tool,
            "ext_exclude": ext_exclude, "mime": mime, "order": order,
            "limit": limit, "offset": offset,
            "fields": fields,
            "max_body": max_body if max_body > 0 else None,
            "mcp": "true" if mcp_only else None,
        })

    def get(self, item_id: int, max_body: int = 1000) -> dict:
        """
        Get full detail for a single traffic item.

        Returns request_text (full) and response_text (body truncated to max_body chars).
        Use max_body=0 for the complete response body.
        """
        return self._get(f"/proxy/history/{item_id}", {
            "max_body": max_body if max_body > 0 else None,
        })

    def repeater_history(
        self,
        host: Optional[str] = None,
        method: Optional[str] = None,
        status: Optional[str] = None,
        search: Optional[str] = None,
        search_in: Optional[str] = None,
        limit: int = 100,
        offset: int = 0,
        fields: Optional[str] = None,
    ) -> list[dict]:
        """List all requests sent from the Repeater tool since extension load."""
        return self._get("/repeater/history", {
            "host": host, "method": method, "status": status,
            "search": search, "search_in": search_in,
            "limit": limit, "offset": offset, "fields": fields,
        })

    def repeater_latest(self, max_body: int = 3000) -> dict:
        """
        Get the most recent Repeater send with full decoded content.
        Use when the user says 'look at what I just sent' or 'check the last Repeater request'.
        Returns request_text and response_text (body truncated to max_body chars).
        """
        return self._get("/repeater/latest", {
            "max_body": max_body if max_body > 0 else None,
        })

    def send_to_repeater(
        self,
        history_id: Optional[int] = None,
        request_b64: Optional[str] = None,
        host: Optional[str] = None,
        port: int = 80,
        https: bool = False,
        tab_name: Optional[str] = None,
    ) -> dict:
        """
        Send a request to Burp Repeater.
        Pass history_id to resend a captured item, or request_b64+host+port+https for raw.
        """
        body = {}
        if history_id is not None:
            body["history_id"] = history_id
        else:
            if not request_b64:
                raise ValueError("Provide either history_id or request_b64")
            body["request"] = request_b64
            body["host"] = host or ""
            body["port"] = port
            body["https"] = https
        if tab_name:
            body["tab_name"] = tab_name
        return self._post("/repeater", body)

    def scope(self, url: str) -> dict:
        """Check whether a URL is in Burp's target scope."""
        return self._get("/scope", {"url": url})

    def request(
        self,
        method: str,
        url: str,
        headers: Optional[dict] = None,
        body: Optional[str] = None,
        proxy_port: int = 8080,
        max_response_body: int = 4000,
    ) -> dict:
        """
        Send an HTTP request through Burp's proxy.
        The request appears in Burp's proxy history. SSL verification is disabled.

        Returns: {status_code, headers, body, url, method}
        """
        try:
            import requests as req_lib
            import urllib3
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        except ImportError:
            raise RuntimeError("pip install requests")

        proxies = {
            "http":  f"http://127.0.0.1:{proxy_port}",
            "https": f"http://127.0.0.1:{proxy_port}",
        }
        # X-Burp-MCP is stripped by the extension before forwarding; tags the item in Burp history
        send_headers = dict(headers or {})
        if "X-Burp-MCP" not in send_headers:
            send_headers["X-Burp-MCP"] = "request"
        resp = req_lib.request(
            method=method.upper(),
            url=url,
            headers=send_headers,
            data=body.encode() if isinstance(body, str) else body,
            proxies=proxies,
            verify=False,
            allow_redirects=False,
        )
        resp_body = resp.text
        if max_response_body > 0 and len(resp_body) > max_response_body:
            resp_body = (resp_body[:max_response_body]
                         + f"\n[... {len(resp_body) - max_response_body} chars omitted]")
        return {
            "status_code": resp.status_code,
            "headers": dict(resp.headers),
            "body": resp_body,
            "url": url,
            "method": method.upper(),
        }

    def repeat(
        self,
        item_id: int,
        replacements: Optional[dict] = None,
        add_headers: Optional[dict] = None,
        body: Optional[str] = None,
        proxy_port: int = 8080,
        max_response_body: int = 4000,
    ) -> dict:
        """
        Fetch a captured request by ID, optionally modify it, and resend through Burp's proxy.
        The repeated request appears in Burp's proxy history.

        Args:
            item_id:          ID from burp_search results
            replacements:     {old: new} string substitutions on the raw request text,
                              e.g. {"Bearer old_token": "Bearer new_token"}
            add_headers:      Headers to add or override, e.g. {"X-Custom": "value"}
            body:             Replace the request body entirely
            proxy_port:       Burp proxy listener port (default 8080)
            max_response_body: Truncate response body (0 = unlimited)
        """
        # Fetch full request, no truncation
        item = self.get(item_id, max_body=0)
        request_text = item.get("request_text", "")
        if not request_text:
            raise RuntimeError(f"No request text for item {item_id}")

        # Apply string replacements to the raw request
        if replacements:
            for old, new in replacements.items():
                request_text = request_text.replace(old, new)

        method, path, headers, req_body = _parse_http_request(request_text)

        # Build URL: scheme from captured item, host from Host header
        scheme = "https" if item.get("url", "").startswith("https") else "http"
        host = _pop_header(headers, "host") or item.get("host", "")
        url = f"{scheme}://{host}{path}"

        # Drop headers requests manages automatically
        for auto in ("content-length", "transfer-encoding"):
            _pop_header(headers, auto)

        if add_headers:
            headers.update(add_headers)
        if body is not None:
            req_body = body

        # Tag this as an MCP repeat so the extension highlights it and it can be filtered
        headers["X-Burp-MCP"] = f"repeat:{item_id}"

        result = self.request(method, url, headers=headers, body=req_body or None,
                              proxy_port=proxy_port, max_response_body=max_response_body)
        result["item_id"] = item_id
        return result

    # ── convenience ───────────────────────────────────────────────────────────

    def print_history(self, items: list[dict]) -> None:
        if not items:
            print("No results.")
            return
        for item in items:
            url = item.get("url") or _build_url(item)
            status = item.get("status_code", 0)
            method = item.get("method", "")
            tool = item.get("tool", "")
            item_id = item.get("id", "")
            ts = (item.get("timestamp") or "")[:19]
            print(f"[{item_id:>6}] {ts}  {tool:<10}  {status}  {method:<7}  {url}")


def _parse_http_request(text: str) -> tuple[str, str, dict, str]:
    """Parse raw HTTP request text into (method, path, headers_dict, body)."""
    text = text.replace("\r\n", "\n").replace("\r", "\n")
    header_part, _, body = text.partition("\n\n")
    lines = header_part.split("\n")
    parts = lines[0].strip().split(" ")
    method = parts[0] if parts else "GET"
    path   = parts[1] if len(parts) > 1 else "/"
    headers = {}
    for line in lines[1:]:
        if ":" in line:
            k, v = line.split(":", 1)
            headers[k.strip()] = v.strip()
    return method, path, headers, body.strip()


def _pop_header(headers: dict, name: str) -> Optional[str]:
    """Case-insensitive header pop."""
    for k in list(headers.keys()):
        if k.lower() == name.lower():
            return headers.pop(k)
    return None


def _build_url(item: dict) -> str:
    """Fallback URL builder when item has host/port/https/path instead of url."""
    scheme = "https" if item.get("https") else "http"
    host = item.get("host", "")
    port = item.get("port", 0)
    path = item.get("path", "")
    default_port = (item.get("https") and port == 443) or (not item.get("https") and port == 80)
    port_str = "" if default_port else f":{port}"
    return f"{scheme}://{host}{port_str}{path}"


# ── CLI ───────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Burp REST Bridge client",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    sub = parser.add_subparsers(dest="cmd", required=True)

    sub.add_parser("health", help="Check extension is running")
    sub.add_parser("hosts",  help="List unique hostnames in captured traffic")
    sub.add_parser("docs",   help="Show API reference")
    sub.add_parser("latest", help="Most recent Repeater send (full decoded content)")

    h = sub.add_parser("history", help="Search proxy/tool history")
    h.add_argument("--host",        help="Filter by hostname (substring)")
    h.add_argument("--method",      help="Filter by HTTP method (GET, POST, ...)")
    h.add_argument("--status",      help="Filter by status code or prefix ('4' for all 4xx)")
    h.add_argument("--search",      help="Search text")
    h.add_argument("--search-in",   dest="search_in",
                   help="Limit search to: request, request_headers, request_body, "
                        "response, response_headers, response_body (comma-separated)")
    h.add_argument("--tool",        help="Filter by tool: PROXY|REPEATER|SCANNER|INTRUDER")
    h.add_argument("--ext-exclude", dest="ext_exclude",
                   help="Exclude URL extensions, e.g. js,css,png,gif,ico,woff2")
    h.add_argument("--mime",        help="Filter by Content-Type substring, e.g. json, html")
    h.add_argument("--order",       choices=["asc", "desc"], default=None,
                   help="asc=oldest first, desc=newest first (default)")
    h.add_argument("--limit",       type=int, default=10)
    h.add_argument("--offset",      type=int, default=0)
    h.add_argument("--fields",      help="Comma-separated fields, e.g. url,status_code,method")
    h.add_argument("--max-body",    type=int, default=0, dest="max_body",
                   help="Truncate body text to N chars (use with --fields including *_text)")

    g = sub.add_parser("get", help="Get full request+response for an item")
    g.add_argument("id", type=int)
    g.add_argument("--max-body", type=int, default=1000, dest="max_body",
                   help="Truncate response body to N chars (0=unlimited, default 1000)")

    r = sub.add_parser("repeater", help="Send a history item to Repeater")
    r.add_argument("id", type=int, help="History item ID")
    r.add_argument("--tab", dest="tab_name", default=None, help="Repeater tab label")

    rp = sub.add_parser("repeat", help="Resend a captured request through Burp proxy, with optional modifications")
    rp.add_argument("id", type=int, help="History item ID to repeat")
    rp.add_argument("--replace", nargs=2, action="append", metavar=("OLD", "NEW"),
                    help="String substitution on raw request (repeatable): --replace 'old' 'new'")
    rp.add_argument("--header", nargs=2, action="append", metavar=("NAME", "VALUE"),
                    help="Add/override a header (repeatable): --header Authorization 'Bearer xyz'")
    rp.add_argument("--body",       default=None, help="Replace request body")
    rp.add_argument("--proxy-port", type=int, default=8080, dest="proxy_port")
    rp.add_argument("--max-body",   type=int, default=4000, dest="max_response_body")

    sc = sub.add_parser("scope", help="Check if URL is in scope")
    sc.add_argument("url")

    args = parser.parse_args()
    client = BurpClient()

    try:
        if args.cmd == "health":
            print(json.dumps(client.health(), indent=2))

        elif args.cmd == "hosts":
            for h in client.hosts():
                print(h)

        elif args.cmd == "docs":
            print(client.docs())

        elif args.cmd == "latest":
            item = client.repeater_latest()
            print(f"[{item['id']}] {item.get('method')} {item.get('url')} → {item.get('status_code')}")
            print("\n=== REQUEST ===")
            print(item.get("request_text", ""))
            print("\n=== RESPONSE ===")
            print(item.get("response_text", ""))

        elif args.cmd == "history":
            items = client.history(
                host=args.host, method=args.method, status=args.status,
                search=args.search, search_in=args.search_in, tool=args.tool,
                ext_exclude=args.ext_exclude, mime=args.mime, order=args.order,
                limit=args.limit, offset=args.offset,
                fields=args.fields, max_body=args.max_body,
            )
            if args.fields:
                print(json.dumps(items, indent=2))
            else:
                client.print_history(items)
                print(f"\n{len(items)} result(s)")

        elif args.cmd == "get":
            item = client.get(args.id, max_body=args.max_body)
            print(f"[{item['id']}] {item.get('method')} {item.get('url')} → {item.get('status_code')}")
            print("\n=== REQUEST ===")
            print(item.get("request_text", ""))
            print("\n=== RESPONSE ===")
            print(item.get("response_text", ""))

        elif args.cmd == "repeater":
            print(json.dumps(client.send_to_repeater(history_id=args.id, tab_name=args.tab_name), indent=2))

        elif args.cmd == "repeat":
            replacements = dict(args.replace) if args.replace else None
            add_headers  = dict(args.header)  if args.header  else None
            result = client.repeat(args.id, replacements=replacements,
                                   add_headers=add_headers, body=args.body,
                                   proxy_port=args.proxy_port,
                                   max_response_body=args.max_response_body)
            print(f"[{result['item_id']}] {result['method']} {result['url']} → {result['status_code']}")
            print("\n=== RESPONSE HEADERS ===")
            for k, v in result["headers"].items():
                print(f"{k}: {v}")
            print("\n=== RESPONSE BODY ===")
            print(result.get("body", ""))

        elif args.cmd == "scope":
            print(json.dumps(client.scope(args.url), indent=2))

    except RuntimeError as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
