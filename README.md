# Burp REST Bridge

A Burp Suite extension + MCP server that lets Claude interact directly with Burp — search proxy
history, read requests/responses, send to Repeater, resend modified requests, and check scope.

## How it works

```
Burp Suite
  └── burp-rest-bridge.jar   Java extension — captures all tool traffic,
                              serves a REST API on http://127.0.0.1:8090

burp_mcp.py                  FastMCP server — wraps the REST API as Claude tools
burp_client.py               Python client — importable library + CLI
```

Claude talks to `burp_mcp.py` via the MCP protocol. The MCP server calls the extension's REST
API. Everything stays on localhost.

## Quick start

```bash
bash setup.sh
```

The script installs Python dependencies, registers the MCP server with Claude Code, and prints
step-by-step instructions for building the JAR and loading it in Burp Suite.

## Claude tools (via MCP)

| Tool | Description |
|---|---|
| `burp_health` | Check the extension is running |
| `burp_hosts` | List all captured hostnames |
| `burp_search` | Search history by host, method, status, text, MIME type, tool, ... |
| `burp_get_item` | Fetch full decoded request + response for one item |
| `burp_repeater_latest` | Get the last request sent from Repeater |
| `burp_send_to_repeater` | Send a captured request to a Repeater tab |
| `burp_repeat` | Re-send a captured request with optional string replacements / header overrides |
| `burp_request` | Send a fully custom HTTP request through Burp's proxy |
| `burp_scope` | Check if a URL is in Burp's target scope |

## CLI usage

```bash
python3 burp_client.py health
python3 burp_client.py hosts
python3 burp_client.py history --host api.example.com --method POST --status 4
python3 burp_client.py get 42
python3 burp_client.py repeat 42 --replace "role=user" "role=admin"
python3 burp_client.py scope https://example.com/admin
```

## REST API (port 8090)

```
GET  /health                  {"status":"ok","count":N,"port":8090}
GET  /proxy/history           search — id, tool, timestamp, url, method, status_code
GET  /proxy/history/{id}      full item — request_text + response_text
GET  /proxy/hosts             sorted list of unique hostnames
GET  /repeater/latest         most recent Repeater send
POST /repeater                send item to Repeater: {"history_id":42,"tab_name":"test"}
GET  /scope?url=...           {"url":"...","in_scope":true}
GET  /                        full API reference
```

## Rebuilding after changes

```bash
cd extension && ./gradlew jar
# Then in Burp: Ctrl+click the Loaded checkbox to hot-reload
```
