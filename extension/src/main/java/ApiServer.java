import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.requests.HttpRequest;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class ApiServer {

    private final MontoyaApi api;
    private final TrafficStore store;
    private final int port;
    private MiniHttpServer server;

    public ApiServer(MontoyaApi api, TrafficStore store, int port) {
        this.api = api;
        this.store = store;
        this.port = port;
    }

    public void start() {
        server = new MiniHttpServer(port);
        server.addRoute("/",              req -> handleDocs(req));
        server.addRoute("/health",        req -> handleHealth(req));
        server.addRoute("/proxy/history", req -> handleProxyHistory(req));
        server.addRoute("/proxy/hosts",   req -> handleHosts(req));
        server.addRoute("/repeater",      req -> handleRepeater(req));
        server.addRoute("/scope",         req -> handleScope(req));
        try {
            server.start();
        } catch (IOException e) {
            api.logging().logToError("Burp REST Bridge: failed to start on port " + port + ": " + e.getMessage());
        }
    }

    public void stop() {
        if (server != null) server.stop();
    }

    // ── / (LLM API docs) ─────────────────────────────────────────────────────

    private MiniHttpServer.Response handleDocs(MiniHttpServer.Request req) {
        if (!"/".equals(req.path())) return json(404, err("Not found"));
        String docs = """
Burp REST Bridge — API reference (port 8090, localhost only)

QUICK START FOR AGENTS
- Confirm running:      GET /health
- See recent traffic:   GET /proxy/history?limit=20
- Filter by host:       GET /proxy/history?host=example.com&limit=20
- Search in responses:  GET /proxy/history?search=token&search_in=response_body&limit=10
- Exclude static files: GET /proxy/history?ext_exclude=js,css,png,gif,woff2,ico&limit=20
- Filter by MIME type:  GET /proxy/history?mime=json&limit=20
- Read a single item:   GET /proxy/history/{id}              (request + 1k of response body)
- Read full response:   GET /proxy/history/{id}?max_body=0
- Oldest occurrence:    GET /proxy/history?search=token&order=asc&limit=1
- MCP-sent requests:   GET /proxy/history?mcp=true&limit=20
- Latest Repeater send: GET /repeater/latest
- Known hosts:          GET /proxy/hosts
- Send to Repeater:     POST /repeater  {"history_id": 42, "tab_name": "test"}
- Check scope:          GET /scope?url=https://example.com

ENDPOINTS

GET /health
  Response: {"status":"ok","count":<total items>,"port":8090}

GET /proxy/history
  Default fields (list): id, tool, timestamp, url, method, status_code
  No request/response bodies in list view — fetch individual items for content.

  Filter params:
    host=<substring>         hostname filter (case-insensitive)
    method=POST              exact HTTP method
    status=<prefix>          "401", "4" (all 4xx), "20" (200-209)
    search=<text>            case-insensitive substring search
    search_in=<parts>        limit search to specific parts (comma-separated):
                               request, request_headers, request_body,
                               response, response_headers, response_body
                             (default: search everywhere)
    ext_exclude=<csv>        exclude by URL extension: js,css,png,gif,ico,woff2,svg,ttf
    mime=<substring>         filter by response Content-Type: "json", "html", "xml"
    tool=PROXY|REPEATER|SCANNER|INTRUDER|EXTENSION
    mcp=true                 only return requests sent via MCP tools (burp_repeat/burp_request)
    order=asc                oldest first (default: newest first)
    limit=100                max results
    offset=0                 pagination

  Output params (use with fields=):
    fields=<csv>             comma-separated fields to include (overrides defaults)
    max_body=<n>             truncate body in *_text fields (0=unlimited); only used
                             when fields= includes request_text or response_text

GET /proxy/history/{id}
  Returns full decoded request + response for a single item.
  Response body truncated to 1000 chars by default.
  Params:
    max_body=0               full response body (no truncation)
    max_body=5000            larger truncation limit
    fields=<csv>             custom field selection

GET /proxy/hosts
  Returns sorted list of unique hostnames seen in captured traffic.
  Response: {"hosts":["api.example.com","app.example.com",...]}

GET /repeater           (or GET /repeater/history)
  Same as /proxy/history but always filtered to tool=REPEATER.
  Supports same filter/output params.

GET /repeater/latest
  Most recent Repeater send with full decoded content (body up to 3000 chars).
  Use when the user says "look at what I just sent" or "check the last Repeater request".

POST /repeater
  Send a request to the Burp Repeater tool (opens a new tab).
  Body options:
    {"history_id": 42}                               — resend a captured item
    {"history_id": 42, "tab_name": "vuln check"}     — with custom tab label
    {"request":"<base64 raw HTTP>",
     "host":"api.example.com","port":443,"https":true}  — raw request
  Response: {"status":"sent","tab_name":"..."}

GET /scope?url=<url>
  Check if a URL is in Burp's suite-wide target scope.
  Response: {"url":"...","in_scope":true}

FIELDS REFERENCE
  id               integer — unique item ID
  tool             string  — PROXY | REPEATER | SCANNER | INTRUDER | EXTENSION
  url              string  — full URL
  method           string  — GET | POST | PUT | DELETE | ...
  status_code      integer — HTTP response status
  timestamp        string  — ISO-8601 capture time
  request_length   integer — raw request size in bytes
  response_length  integer — raw response size in bytes
  host             string  — hostname only
  port             integer — port number
  https            boolean — TLS/HTTPS
  path             string  — path+query only
  request          string  — base64-encoded raw request
  response         string  — base64-encoded raw response
  request_text     string  — decoded request (headers always full; body truncated at max_body)
  response_text    string  — decoded response (headers always full; body truncated at max_body)
  response_headers string  — response status line + headers only (no body)
  mcp_tag       string  — present only on Claude-initiated requests (e.g. "repeat:42", "request")
""";
        return new MiniHttpServer.Response(200, docs, "text/plain; charset=utf-8");
    }

    // ── /health ───────────────────────────────────────────────────────────────

    private MiniHttpServer.Response handleHealth(MiniHttpServer.Request req) {
        return json(200, "{\"status\":\"ok\",\"count\":" + store.size() + ",\"port\":" + port + "}");
    }

    // ── /proxy/hosts ──────────────────────────────────────────────────────────

    private MiniHttpServer.Response handleHosts(MiniHttpServer.Request req) {
        List<String> hosts = store.getHosts();
        StringBuilder sb = new StringBuilder("{\"hosts\":[");
        for (int i = 0; i < hosts.size(); i++) {
            if (i > 0) sb.append(",");
            sb.append("\"").append(TrafficItem.escapeJson(hosts.get(i))).append("\"");
        }
        sb.append("]}");
        return json(200, sb.toString());
    }

    // ── /proxy/history[/{id}] ─────────────────────────────────────────────────

    private MiniHttpServer.Response handleProxyHistory(MiniHttpServer.Request req) {
        if (!"GET".equals(req.method())) return json(405, err("Method not allowed"));

        String path = req.path();
        String prefix = "/proxy/history/";

        // Detail: /proxy/history/{id}
        if (path.startsWith(prefix)) {
            String idStr = path.substring(prefix.length());
            try {
                long id = Long.parseLong(idStr);
                TrafficItem item = store.getById(id);
                if (item == null) return json(404, err("Item not found"));
                return json(200, renderDetail(item, req.params()));
            } catch (NumberFormatException e) {
                return json(400, err("Invalid id: " + idStr));
            }
        }

        // List
        return json(200, searchToJson(req.params(), null));
    }

    // ── /repeater ─────────────────────────────────────────────────────────────

    private MiniHttpServer.Response handleRepeater(MiniHttpServer.Request req) {
        String path = req.path();

        // GET /repeater/latest — most recent Repeater send
        if ("GET".equals(req.method()) && path.endsWith("/latest")) {
            TrafficItem item = store.getLatestByTool("REPEATER");
            if (item == null) return json(404, err("No Repeater sends captured yet. Send a request from a Repeater tab first."));
            Map<String, String> params = new LinkedHashMap<>(req.params());
            params.putIfAbsent("max_body", "3000");
            return json(200, renderDetail(item, params));
        }

        // GET /repeater or GET /repeater/history — list
        if ("GET".equals(req.method())) {
            return json(200, searchToJson(req.params(), "REPEATER"));
        }

        // POST /repeater — send to Repeater tab
        if (!"POST".equals(req.method())) return json(405, err("Method not allowed"));

        String bodyStr = new String(req.body(), StandardCharsets.UTF_8);
        Map<String, String> jsonBody = parseSimpleJson(bodyStr);

        try {
            byte[] requestBytes;
            String host;
            int sendPort;
            boolean secure;

            String historyIdStr = jsonBody.get("history_id");
            if (historyIdStr != null && !historyIdStr.isEmpty()) {
                long histId = Long.parseLong(historyIdStr);
                TrafficItem item = store.getById(histId);
                if (item == null) return json(404, err("History item not found: " + histId));
                requestBytes = item.requestBytes;
                host     = item.host;
                sendPort = item.port;
                secure   = item.https;
            } else {
                String requestB64 = jsonBody.get("request");
                if (requestB64 == null || requestB64.isEmpty())
                    return json(400, err("Provide either 'history_id' or 'request' (base64 raw HTTP request)"));
                try {
                    requestBytes = java.util.Base64.getDecoder().decode(requestB64);
                } catch (IllegalArgumentException e) {
                    return json(400, err("Invalid base64 in 'request'"));
                }
                host     = jsonBody.getOrDefault("host", "");
                sendPort = parseIntOr(jsonBody.get("port"), 80);
                secure   = "true".equalsIgnoreCase(jsonBody.getOrDefault("https", "false"));
            }

            String tabName = jsonBody.get("tab_name");
            HttpService service = HttpService.httpService(host, sendPort, secure);
            HttpRequest httpReq = HttpRequest.httpRequest(service, ByteArray.byteArray(requestBytes));

            if (tabName != null && !tabName.isEmpty()) {
                api.repeater().sendToRepeater(httpReq, tabName);
            } else {
                api.repeater().sendToRepeater(httpReq);
            }

            return json(200, "{\"status\":\"sent\",\"tab_name\":"
                    + (tabName != null ? "\"" + TrafficItem.escapeJson(tabName) + "\"" : "null") + "}");

        } catch (NumberFormatException e) {
            return json(400, err("Invalid number: " + e.getMessage()));
        } catch (Exception e) {
            return json(500, err(e.getMessage()));
        }
    }

    // ── /scope ────────────────────────────────────────────────────────────────

    private MiniHttpServer.Response handleScope(MiniHttpServer.Request req) {
        if (!"GET".equals(req.method())) return json(405, err("Method not allowed"));
        String url = req.params().get("url");
        if (url == null || url.isEmpty()) return json(400, err("Missing required query param: url"));
        boolean inScope = api.scope().isInScope(url);
        return json(200, "{\"url\":\"" + TrafficItem.escapeJson(url) + "\",\"in_scope\":" + inScope + "}");
    }

    // ── helpers ───────────────────────────────────────────────────────────────

    /**
     * Render a single item as JSON.
     * Default: request_text + response_text with body truncated to 1000 chars.
     * Override with max_body=0 for full body, or fields= for custom field set.
     */
    private String renderDetail(TrafficItem item, Map<String, String> params) {
        int maxBody = parseIntOr(params.get("max_body"), 1000);
        Set<String> fields = parseFields(params.get("fields"));
        if (fields != null) {
            return item.toJson(fields, maxBody);
        }
        return item.toJsonDetail(maxBody);
    }

    /** Run a search and serialise results as a JSON array. */
    private String searchToJson(Map<String, String> params, String forceTool) {
        String host       = params.get("host");
        String method     = params.get("method");
        String status     = params.get("status");
        String search     = params.get("search");
        String searchIn   = params.get("search_in");
        String tool       = forceTool != null ? forceTool : params.get("tool");
        String extExclude = params.get("ext_exclude");
        String mime       = params.get("mime");
        String order      = params.get("order");
        boolean mcpOnly = "true".equalsIgnoreCase(params.get("mcp"));
        int limit         = parseIntOr(params.get("limit"), 100);
        int offset        = parseIntOr(params.get("offset"), 0);
        int maxBody       = parseIntOr(params.get("max_body"), 0);
        Set<String> fields = parseFields(params.get("fields"));

        List<TrafficItem> results = store.search(
                host, method, status, search, searchIn, tool,
                extExclude, mime, limit, offset, order, mcpOnly);

        StringBuilder sb = new StringBuilder("[");
        for (int i = 0; i < results.size(); i++) {
            if (i > 0) sb.append(",");
            TrafficItem item = results.get(i);
            if (fields != null) {
                sb.append(item.toJson(fields, maxBody));
            } else {
                sb.append(item.toJsonList());
            }
        }
        sb.append("]");
        return sb.toString();
    }

    /** Parse "field1,field2" into a Set, or return null if blank. */
    private static Set<String> parseFields(String fieldsParam) {
        if (fieldsParam == null || fieldsParam.isEmpty()) return null;
        Set<String> set = new LinkedHashSet<>();
        for (String f : fieldsParam.split(",")) {
            String trimmed = f.trim();
            if (!trimmed.isEmpty()) set.add(trimmed);
        }
        return set.isEmpty() ? null : set;
    }

    private static MiniHttpServer.Response json(int status, String body) {
        return new MiniHttpServer.Response(status, body);
    }

    private static String err(String msg) {
        return "{\"error\":\"" + TrafficItem.escapeJson(msg) + "\"}";
    }

    private static Map<String, String> parseSimpleJson(String json) {
        Map<String, String> result = new LinkedHashMap<>();
        if (json == null || json.isEmpty()) return result;

        Matcher strings = Pattern.compile("\"([^\"]+)\"\\s*:\\s*\"((?:[^\"\\\\]|\\\\.)*)\"\n").matcher(json);
        while (strings.find()) result.put(strings.group(1), unescapeJson(strings.group(2)));

        Matcher strings2 = Pattern.compile("\"([^\"]+)\"\\s*:\\s*\"((?:[^\"\\\\]|\\\\.)*)\"").matcher(json);
        while (strings2.find()) result.putIfAbsent(strings2.group(1), unescapeJson(strings2.group(2)));

        Matcher numbers = Pattern.compile("\"([^\"]+)\"\\s*:\\s*(-?\\d+(?:\\.\\d+)?)").matcher(json);
        while (numbers.find()) result.putIfAbsent(numbers.group(1), numbers.group(2));

        Matcher bools = Pattern.compile("\"([^\"]+)\"\\s*:\\s*(true|false)").matcher(json);
        while (bools.find()) result.putIfAbsent(bools.group(1), bools.group(2));

        return result;
    }

    private static String unescapeJson(String s) {
        return s.replace("\\\"", "\"").replace("\\\\", "\\")
                .replace("\\n", "\n").replace("\\r", "\r").replace("\\t", "\t");
    }

    private static int parseIntOr(String s, int defaultVal) {
        if (s == null || s.isEmpty()) return defaultVal;
        try { return Integer.parseInt(s); } catch (NumberFormatException e) { return defaultVal; }
    }
}
