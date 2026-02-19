# Burp REST Bridge

Burp Suite extension + MCP server that lets Claude interact with Burp (search proxy history,
read requests/responses, send to Repeater, check scope).

## Project layout

```
extension/          Java source + Gradle build
  src/main/java/
    Extension.java      Entry point (BurpExtension), registers HTTP handler + startup backfill
    TrafficItem.java    Immutable data model, JSON serialisation, gzip decompress
    TrafficStore.java   Thread-safe in-memory store (50k items max, LRU eviction)
    ApiServer.java      REST endpoints on port 8090 (localhost only)
    MiniHttpServer.java Minimal HTTP/1.1 server using java.net.ServerSocket (java.base only)
  build/libs/burp-rest-bridge.jar   ← built artifact, load this in Burp
burp_client.py      Python 3 client (importable + CLI)
burp_mcp.py         FastMCP server — gives Claude native tools
setup.sh            One-shot setup: installs fastmcp, registers MCP, prints Burp instructions
```

## Build the JAR

```bash
cd extension
./gradlew jar           # output: build/libs/burp-rest-bridge.jar
# If no system Java: JAVA_HOME=/snap/datagrip/256/jbr ./gradlew jar
```

To reload in Burp after rebuilding: Ctrl+click the Loaded checkbox next to the extension.

## REST API (port 8090, localhost only)

All responses are decoded text (no base64 by default). `max_body` truncates the body only —
headers are always returned in full.

| Endpoint | Description |
|---|---|
| `GET /health` | `{"status":"ok","count":N,"port":8090}` |
| `GET /proxy/history` | Search traffic — returns `id,tool,timestamp,url,method,status_code` |
| `GET /proxy/history/{id}` | Full item — `request_text` + `response_text` (body truncated to 1k default) |
| `GET /proxy/hosts` | Sorted list of unique hostnames |
| `GET /repeater/latest` | Most recent Repeater send, decoded (body up to 3k) |
| `POST /repeater` | Send item to Repeater: `{"history_id":42,"tab_name":"test"}` |
| `GET /scope?url=...` | `{"url":"...","in_scope":true}` |
| `GET /` | Full API reference (plain text) |

### History search params

```
host=<substring>       ext_exclude=js,css,png,gif    order=asc (oldest first)
method=POST            mime=json                      limit=100  offset=0
status=4               tool=PROXY|REPEATER|...        fields=url,status_code
search=<text>          search_in=request_headers,response_body
max_body=0             (0 = unlimited, applies to body only)
```

## MCP tools (via burp_mcp.py)

`burp_health` · `burp_hosts` · `burp_search` · `burp_get_item` ·
`burp_repeater_latest` · `burp_send_to_repeater` · `burp_scope` ·
`burp_repeat` · `burp_request`

### burp_repeat
Fetches a captured request by ID, applies string replacements to the raw request text,
optionally overrides headers or body, then sends through Burp's proxy (port 8080 default).
The repeated request appears in Burp's proxy history.
- `replacements`: `{"Bearer old": "Bearer new"}` — raw text substitution
- `add_headers`: `{"X-Forwarded-For": "127.0.0.1"}` — inject/override headers
- `body`: replace body entirely

### burp_request
Send a fully custom HTTP request through Burp's proxy. Appears in history as tool=PROXY.

## Montoya API notes

- Correct import: `burp.api.montoya.http.handler.HttpHandler` (not `http.HttpHandler`)
- `HttpResponseReceived.initiatingRequest()` correlates response → request directly
- `api.http().registerHttpHandler()` captures all tools (PROXY, REPEATER, SCANNER, ...)
- `api.proxy().history()` returns `List<ProxyHttpRequestResponse>` for startup backfill
- `com.sun.net.httpserver` is NOT accessible from Burp's classloader — use MiniHttpServer
- `ByteArray.getBytes()` returns `byte[]`
