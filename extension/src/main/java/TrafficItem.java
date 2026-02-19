import burp.api.montoya.http.handler.HttpResponseReceived;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.proxy.ProxyHttpRequestResponse;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Arrays;
import java.util.Base64;
import java.util.Locale;
import java.util.Set;
import java.util.concurrent.atomic.AtomicLong;
import java.util.zip.GZIPInputStream;

public class TrafficItem {

    static final AtomicLong COUNTER = new AtomicLong(0);

    public final long id;
    public final String tool;
    public final Instant timestamp;
    public final String host;
    public final int port;
    public final boolean https;
    public final String method;
    public final String path;
    public final int statusCode;
    public final byte[] requestBytes;
    public final byte[] responseBytes;
    /** Non-null for requests sent by Claude via burp_repeat/burp_request. E.g. "repeat:42". */
    public final String mcpTag;

    public TrafficItem(String tool, String host, int port, boolean https,
                       String method, String path, int statusCode,
                       byte[] requestBytes, byte[] responseBytes, String mcpTag) {
        this.id = COUNTER.incrementAndGet();
        this.tool = tool;
        this.timestamp = Instant.now();
        this.host = host != null ? host : "";
        this.port = port;
        this.https = https;
        this.method = method != null ? method : "";
        this.path = path != null ? path : "";
        this.statusCode = statusCode;
        this.requestBytes = requestBytes != null ? requestBytes : new byte[0];
        this.responseBytes = responseBytes != null ? responseBytes : new byte[0];
        this.mcpTag = mcpTag;
    }

    // ── factory methods ───────────────────────────────────────────────────────

    public static TrafficItem fromLiveResponse(HttpResponseReceived response, String mcpTag) {
        HttpRequest req = response.initiatingRequest();
        HttpService svc = req != null ? req.httpService() : null;
        return new TrafficItem(
                response.toolSource().toolType().name(),
                svc != null ? svc.host() : "",
                svc != null ? svc.port() : 0,
                svc != null && svc.secure(),
                req != null ? req.method() : "",
                req != null ? req.path() : "",
                response.statusCode(),
                req != null ? req.toByteArray().getBytes() : new byte[0],
                response.toByteArray().getBytes(),
                mcpTag
        );
    }

    public static TrafficItem fromHistoryItem(ProxyHttpRequestResponse item) {
        HttpRequest req = item.request();
        HttpResponse resp = item.response();
        HttpService svc = req != null ? req.httpService() : null;
        return new TrafficItem(
                "PROXY",
                svc != null ? svc.host() : "",
                svc != null ? svc.port() : 0,
                svc != null && svc.secure(),
                req != null ? req.method() : "",
                req != null ? req.path() : "",
                resp != null ? resp.statusCode() : 0,
                req != null ? req.toByteArray().getBytes() : new byte[0],
                resp != null ? resp.toByteArray().getBytes() : new byte[0],
                null
        );
    }

    // ── URL convenience ───────────────────────────────────────────────────────

    public String url() {
        String scheme = https ? "https" : "http";
        boolean defaultPort = (https && port == 443) || (!https && port == 80);
        String portStr = defaultPort ? "" : ":" + port;
        return scheme + "://" + host + portStr + path;
    }

    // ── filter helpers ────────────────────────────────────────────────────────

    /** File extension from URL path, lower-cased. E.g. "js", "png", "" if none. */
    public String getUrlExtension() {
        int q = path.indexOf('?');
        String pathOnly = q >= 0 ? path.substring(0, q) : path;
        int lastSlash = pathOnly.lastIndexOf('/');
        String filename = pathOnly.substring(lastSlash + 1);
        int dot = filename.lastIndexOf('.');
        if (dot < 0 || dot == filename.length() - 1) return "";
        return filename.substring(dot + 1).toLowerCase(Locale.ROOT);
    }

    /** Content-Type value from response headers, lower-cased. Empty string if absent. */
    public String getContentType() {
        if (responseBytes == null || responseBytes.length == 0) return "";
        int sep = findBodySep(responseBytes);
        String headers = sep >= 0
                ? new String(Arrays.copyOfRange(responseBytes, 0, sep), StandardCharsets.ISO_8859_1)
                : new String(responseBytes, StandardCharsets.ISO_8859_1);
        for (String line : headers.split("\r?\n")) {
            if (line.toLowerCase(Locale.ROOT).startsWith("content-type:")) {
                return line.substring("content-type:".length()).trim().toLowerCase(Locale.ROOT);
            }
        }
        return "";
    }

    /**
     * Search within specific parts of the request/response.
     * Valid part names: request, request_headers, request_body,
     *                   response, response_headers, response_body
     */
    public boolean containsSearchIn(String search, Set<String> parts) {
        String needle = search.toLowerCase(Locale.ROOT);
        for (String part : parts) {
            if (matchesPart(needle, part)) return true;
        }
        return false;
    }

    private boolean matchesPart(String needle, String part) {
        return switch (part) {
            case "request"          -> containsBytes(requestBytes, needle, false);
            case "request_headers"  -> containsBytesHeaders(requestBytes, needle);
            case "request_body"     -> containsBytesBody(requestBytes, needle, false);
            case "response"         -> containsBytes(responseBytes, needle, true);
            case "response_headers" -> containsBytesHeaders(responseBytes, needle);
            case "response_body"    -> containsBytesBody(responseBytes, needle, true);
            default                 -> false;
        };
    }

    private static boolean containsBytes(byte[] raw, String needle, boolean tryGzip) {
        if (raw == null || raw.length == 0) return false;
        return decodeForDisplay(raw, 0, tryGzip).toLowerCase(Locale.ROOT).contains(needle);
    }

    private static boolean containsBytesHeaders(byte[] raw, String needle) {
        if (raw == null || raw.length == 0) return false;
        int sep = findBodySep(raw);
        String headers = sep >= 0
                ? new String(Arrays.copyOfRange(raw, 0, sep), StandardCharsets.ISO_8859_1)
                : new String(raw, StandardCharsets.ISO_8859_1);
        return headers.toLowerCase(Locale.ROOT).contains(needle);
    }

    private static boolean containsBytesBody(byte[] raw, String needle, boolean tryGzip) {
        if (raw == null || raw.length == 0) return false;
        int sep = findBodySep(raw);
        if (sep < 0) return false;
        int bodyStart = (raw[sep] == '\r') ? sep + 4 : sep + 2;
        if (bodyStart >= raw.length) return false;
        byte[] body = Arrays.copyOfRange(raw, bodyStart, raw.length);
        if (tryGzip) {
            String headers = new String(Arrays.copyOfRange(raw, 0, sep), StandardCharsets.ISO_8859_1);
            if (headers.toLowerCase(Locale.ROOT).contains("content-encoding: gzip")) {
                try { body = new GZIPInputStream(new ByteArrayInputStream(body)).readAllBytes(); }
                catch (IOException ignored) {}
            }
        }
        return new String(body, StandardCharsets.UTF_8).toLowerCase(Locale.ROOT).contains(needle);
    }

    // ── JSON serialisation ────────────────────────────────────────────────────

    /**
     * Serialise to JSON with the given field set.
     *
     * Available fields:
     *   id, tool, url, host, port, https, method, path,
     *   status_code, timestamp, request_length, response_length,
     *   request (base64), response (base64),
     *   request_text, response_text, response_headers
     *
     * maxBody: truncates the *body portion only* of request_text/response_text
     *          (headers always included in full). 0 = unlimited.
     */
    public String toJson(Set<String> fields, int maxBody) {
        final boolean all = (fields == null || fields.isEmpty());
        java.util.function.Predicate<String> has = f -> all || fields.contains(f);

        StringBuilder sb = new StringBuilder("{");
        boolean first = true;

        if (has.test("id"))               { first = comma(sb, first); appendLong(sb, "id",               id); }
        if (has.test("tool"))             { first = comma(sb, first); appendStr(sb,  "tool",             tool); }
        if (has.test("url"))              { first = comma(sb, first); appendStr(sb,  "url",              url()); }
        if (has.test("host"))             { first = comma(sb, first); appendStr(sb,  "host",             host); }
        if (has.test("port"))             { first = comma(sb, first); appendLong(sb, "port",             port); }
        if (has.test("https"))            { first = comma(sb, first); appendBool(sb, "https",            https); }
        if (has.test("method"))           { first = comma(sb, first); appendStr(sb,  "method",           method); }
        if (has.test("path"))             { first = comma(sb, first); appendStr(sb,  "path",             path); }
        if (has.test("status_code"))      { first = comma(sb, first); appendLong(sb, "status_code",      statusCode); }
        if (has.test("timestamp"))        { first = comma(sb, first); appendStr(sb,  "timestamp",        timestamp.toString()); }
        if (has.test("request_length"))   { first = comma(sb, first); appendLong(sb, "request_length",   requestBytes.length); }
        if (has.test("response_length"))  { first = comma(sb, first); appendLong(sb, "response_length",  responseBytes.length); }
        if (has.test("request"))          { first = comma(sb, first); appendStr(sb,  "request",          Base64.getEncoder().encodeToString(requestBytes)); }
        if (has.test("response"))         { first = comma(sb, first); appendStr(sb,  "response",         Base64.getEncoder().encodeToString(responseBytes)); }
        if (has.test("request_text"))     { first = comma(sb, first); appendStr(sb,  "request_text",     decodeForDisplay(requestBytes, maxBody, false)); }
        if (has.test("response_text"))    { first = comma(sb, first); appendStr(sb,  "response_text",    decodeForDisplay(responseBytes, maxBody, true)); }
        if (has.test("response_headers")) { first = comma(sb, first); appendStr(sb,  "response_headers", extractResponseHeaders()); }
        // mcp_tag: only emitted when non-null (i.e. request was sent by Claude)
        if (mcpTag != null && has.test("mcp_tag")) { first = comma(sb, first); appendStr(sb, "mcp_tag", mcpTag); }

        sb.append("}");
        return sb.toString();
    }

    /** List view: id, tool, timestamp, url, method, status_code — no bodies. */
    public String toJsonList() {
        return toJson(DEFAULT_LIST_FIELDS, 0);
    }

    /**
     * Detail view: full request text + response text truncated to maxBody chars in body.
     * Pass maxBody=0 for unlimited. Default detail call uses maxBody=1000.
     */
    public String toJsonDetail(int maxBody) {
        return toJson(DEFAULT_DETAIL_FIELDS, maxBody);
    }

    // List: minimal metadata only (mcp_tag included but only emitted when non-null)
    private static final Set<String> DEFAULT_LIST_FIELDS = Set.of(
            "id", "tool", "timestamp", "url", "method", "status_code", "mcp_tag");

    // Detail: full request + response truncated at body (mcp_tag included but only emitted when non-null)
    private static final Set<String> DEFAULT_DETAIL_FIELDS = Set.of(
            "id", "tool", "url", "method", "status_code", "timestamp",
            "request_length", "response_length", "request_text", "response_text", "mcp_tag");

    // ── decode / decompress ───────────────────────────────────────────────────

    /**
     * Decode raw HTTP message bytes to a human-readable string.
     * Splits on the header/body separator; maxBody truncates the body portion only
     * (headers are always returned in full). For responses, decompresses gzip bodies.
     * maxBody=0 means unlimited.
     */
    public static String decodeForDisplay(byte[] raw, int maxBody, boolean tryGzip) {
        if (raw == null || raw.length == 0) return "";

        int sep = findBodySep(raw);

        if (sep < 0) {
            // No separator — treat entire bytes as body
            String text = new String(raw, StandardCharsets.ISO_8859_1);
            return truncateBody(text, maxBody);
        }

        String headers  = new String(Arrays.copyOfRange(raw, 0, sep), StandardCharsets.ISO_8859_1);
        int bodyStart   = (raw[sep] == '\r') ? sep + 4 : sep + 2;
        byte[] bodyBytes = bodyStart < raw.length
                ? Arrays.copyOfRange(raw, bodyStart, raw.length)
                : new byte[0];

        // Gzip decompression for responses
        if (tryGzip && headers.toLowerCase(Locale.ROOT).contains("content-encoding: gzip")) {
            try { bodyBytes = new GZIPInputStream(new ByteArrayInputStream(bodyBytes)).readAllBytes(); }
            catch (IOException ignored) {}
        }

        String bodyStr = tryGzip
                ? new String(bodyBytes, StandardCharsets.UTF_8)
                : new String(bodyBytes, StandardCharsets.ISO_8859_1);

        return headers + "\r\n\r\n" + truncateBody(bodyStr, maxBody);
    }

    private static String truncateBody(String body, int maxBody) {
        if (maxBody <= 0 || body.length() <= maxBody) return body;
        return body.substring(0, maxBody)
                + "\n[... " + (body.length() - maxBody) + " chars omitted — use ?max_body=0 for full body]";
    }

    /** Extract only the response headers (everything before \\r\\n\\r\\n). */
    private String extractResponseHeaders() {
        if (responseBytes == null || responseBytes.length == 0) return "";
        int sep = findBodySep(responseBytes);
        if (sep < 0) return new String(responseBytes, StandardCharsets.ISO_8859_1);
        return new String(Arrays.copyOfRange(responseBytes, 0, sep), StandardCharsets.ISO_8859_1);
    }

    static int findBodySep(byte[] raw) {
        for (int i = 0; i < raw.length - 3; i++) {
            if (raw[i] == '\r' && raw[i+1] == '\n' && raw[i+2] == '\r' && raw[i+3] == '\n')
                return i;
        }
        for (int i = 0; i < raw.length - 1; i++) {
            if (raw[i] == '\n' && raw[i+1] == '\n') return i;
        }
        return -1;
    }

    // ── JSON helpers ──────────────────────────────────────────────────────────

    private static boolean comma(StringBuilder sb, boolean first) {
        if (!first) sb.append(",");
        return false;
    }

    private static void appendStr(StringBuilder sb, String key, String value) {
        sb.append("\"").append(key).append("\":\"").append(escapeJson(value)).append("\"");
    }

    private static void appendLong(StringBuilder sb, String key, long value) {
        sb.append("\"").append(key).append("\":").append(value);
    }

    private static void appendBool(StringBuilder sb, String key, boolean value) {
        sb.append("\"").append(key).append("\":").append(value);
    }

    public static String escapeJson(String s) {
        if (s == null) return "";
        return s.replace("\\", "\\\\")
                .replace("\"", "\\\"")
                .replace("\n", "\\n")
                .replace("\r", "\\r")
                .replace("\t", "\\t")
                .replace("\u0000", "");
    }
}
