import java.io.*;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.concurrent.*;
import java.util.function.Function;

/**
 * Minimal HTTP/1.1 server built on java.net.ServerSocket (java.base only).
 * Used instead of com.sun.net.httpserver which is inaccessible from
 * Burp's extension classloader.
 */
public class MiniHttpServer {

    public record Request(
            String method,
            String path,           // URL-decoded path, e.g. /proxy/history/42
            Map<String, String> params,  // URL-decoded query params
            byte[] body
    ) {}

    public record Response(int status, String body, String contentType) {
        public Response(int status, String body) { this(status, body, "application/json"); }
    }

    private record Route(String prefix, Function<Request, Response> handler) {}

    private final int port;
    private ServerSocket serverSocket;
    private ExecutorService executor;
    private volatile boolean running;
    private final List<Route> routes = new ArrayList<>();

    public MiniHttpServer(int port) {
        this.port = port;
    }

    /** Register a handler for all requests whose path equals or starts with prefix. */
    public void addRoute(String prefix, Function<Request, Response> handler) {
        routes.add(new Route(prefix, handler));
    }

    public void start() throws IOException {
        serverSocket = new ServerSocket();
        serverSocket.setReuseAddress(true);
        serverSocket.bind(new InetSocketAddress("127.0.0.1", port));
        executor = Executors.newCachedThreadPool(r -> {
            Thread t = new Thread(r, "BurpRestBridge-Worker");
            t.setDaemon(true);
            return t;
        });
        running = true;
        Thread acceptThread = new Thread(this::acceptLoop, "BurpRestBridge-Accept");
        acceptThread.setDaemon(true);
        acceptThread.start();
    }

    public void stop() {
        running = false;
        try { serverSocket.close(); } catch (IOException ignored) {}
        if (executor != null) executor.shutdown();
    }

    // ── internals ─────────────────────────────────────────────────────────────

    private void acceptLoop() {
        while (running) {
            try {
                Socket socket = serverSocket.accept();
                socket.setSoTimeout(10_000);
                executor.submit(() -> handleConnection(socket));
            } catch (IOException e) {
                // ServerSocket closed — normal shutdown
            }
        }
    }

    private void handleConnection(Socket socket) {
        try (socket) {
            Request req = parseRequest(new BufferedInputStream(socket.getInputStream()));
            if (req == null) return;
            Response resp = dispatch(req);
            sendResponse(new BufferedOutputStream(socket.getOutputStream()), resp);
        } catch (Exception ignored) {}
    }

    private Request parseRequest(InputStream in) throws IOException {
        String requestLine = readLine(in);
        if (requestLine == null || requestLine.isEmpty()) return null;

        String[] parts = requestLine.split(" ", 3);
        if (parts.length < 2) return null;
        String method = parts[0];
        String fullPath = parts[1];

        // Split path from query string
        int qIdx = fullPath.indexOf('?');
        String rawPath  = qIdx >= 0 ? fullPath.substring(0, qIdx) : fullPath;
        String rawQuery = qIdx >= 0 ? fullPath.substring(qIdx + 1) : null;

        String path;
        try { path = URLDecoder.decode(rawPath, StandardCharsets.UTF_8); }
        catch (Exception e) { path = rawPath; }

        // Consume headers
        Map<String, String> headers = new LinkedHashMap<>();
        String headerLine;
        while (!(headerLine = readLine(in)).isEmpty()) {
            int colon = headerLine.indexOf(':');
            if (colon > 0) {
                headers.put(headerLine.substring(0, colon).toLowerCase(Locale.ROOT).trim(),
                            headerLine.substring(colon + 1).trim());
            }
        }

        // Read body if Content-Length is set
        byte[] body = new byte[0];
        String cl = headers.get("content-length");
        if (cl != null) {
            try {
                int len = Integer.parseInt(cl.trim());
                body = in.readNBytes(len);
            } catch (NumberFormatException ignored) {}
        }

        return new Request(method, path, parseQuery(rawQuery), body);
    }

    private Response dispatch(Request req) {
        for (Route route : routes) {
            if (req.path().equals(route.prefix()) ||
                    req.path().startsWith(route.prefix() + "/")) {
                try {
                    return route.handler().apply(req);
                } catch (Exception e) {
                    return new Response(500,
                            "{\"error\":\"" + TrafficItem.escapeJson(e.getMessage()) + "\"}");
                }
            }
        }
        return new Response(404, "{\"error\":\"Not found\"}");
    }

    private void sendResponse(OutputStream out, Response resp) throws IOException {
        String statusText = switch (resp.status()) {
            case 200 -> "OK";
            case 400 -> "Bad Request";
            case 404 -> "Not Found";
            case 405 -> "Method Not Allowed";
            default  -> "Internal Server Error";
        };
        byte[] body = resp.body().getBytes(StandardCharsets.UTF_8);
        String head = "HTTP/1.1 " + resp.status() + " " + statusText + "\r\n"
                + "Content-Type: " + resp.contentType() + "\r\n"
                + "Content-Length: " + body.length + "\r\n"
                + "Access-Control-Allow-Origin: *\r\n"
                + "Connection: close\r\n"
                + "\r\n";
        out.write(head.getBytes(StandardCharsets.UTF_8));
        out.write(body);
        out.flush();
    }

    private static String readLine(InputStream in) throws IOException {
        StringBuilder sb = new StringBuilder();
        int b;
        while ((b = in.read()) != -1) {
            if (b == '\r') { in.read(); break; }  // consume \n
            if (b == '\n') break;
            sb.append((char) b);
        }
        return sb.toString();
    }

    private static Map<String, String> parseQuery(String query) {
        Map<String, String> params = new LinkedHashMap<>();
        if (query == null || query.isEmpty()) return params;
        for (String pair : query.split("&")) {
            int idx = pair.indexOf('=');
            if (idx > 0) {
                try {
                    params.put(URLDecoder.decode(pair.substring(0, idx), StandardCharsets.UTF_8),
                               URLDecoder.decode(pair.substring(idx + 1), StandardCharsets.UTF_8));
                } catch (Exception ignored) {}
            }
        }
        return params;
    }
}
