import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.Annotations;
import burp.api.montoya.core.HighlightColor;
import burp.api.montoya.http.handler.HttpHandler;
import burp.api.montoya.http.handler.HttpRequestToBeSent;
import burp.api.montoya.http.handler.HttpResponseReceived;
import burp.api.montoya.http.handler.RequestToBeSentAction;
import burp.api.montoya.http.handler.ResponseReceivedAction;
import burp.api.montoya.http.message.requests.HttpRequest;

import java.util.concurrent.ConcurrentHashMap;

public class Extension implements BurpExtension {

    private ApiServer server;

    /**
     * Fingerprint a request for correlation between handleHttpRequestToBeSent
     * and handleHttpResponseReceived. Uses method + host + path + byte-length
     * of the stripped request (without X-Burp-MCP header).
     */
    private static String fingerprint(HttpRequest req) {
        String host = req.httpService() != null ? req.httpService().host() : "";
        return req.method() + " " + host + req.path() + " " + req.toByteArray().length();
    }

    @Override
    public void initialize(MontoyaApi api) {
        api.extension().setName("Burp REST Bridge");

        TrafficStore store = new TrafficStore();

        // Track in-flight MCP-initiated requests: fingerprint → mcp_tag
        ConcurrentHashMap<String, String> pendingMcpTags = new ConcurrentHashMap<>();

        // Capture all tool traffic in real-time (Proxy, Repeater, Intruder, Scanner, etc.)
        api.http().registerHttpHandler(new HttpHandler() {
            @Override
            public RequestToBeSentAction handleHttpRequestToBeSent(HttpRequestToBeSent request) {
                String mcpTag = request.headerValue("X-Burp-MCP");
                if (mcpTag != null && !mcpTag.isEmpty()) {
                    // Strip the internal header before forwarding to the server
                    HttpRequest stripped = request.withRemovedHeader("X-Burp-MCP");
                    pendingMcpTags.put(fingerprint(stripped), mcpTag);
                    // Highlight in Burp UI: cyan + annotation note
                    Annotations ann = request.annotations()
                            .withHighlightColor(HighlightColor.CYAN)
                            .withNotes("MCP: " + mcpTag);
                    return RequestToBeSentAction.continueWith(stripped, ann);
                }
                return RequestToBeSentAction.continueWith(request);
            }

            @Override
            public ResponseReceivedAction handleHttpResponseReceived(HttpResponseReceived response) {
                try {
                    String mcpTag = null;
                    HttpRequest req = response.initiatingRequest();
                    if (req != null) {
                        mcpTag = pendingMcpTags.remove(fingerprint(req));
                    }
                    store.add(TrafficItem.fromLiveResponse(response, mcpTag));
                } catch (Exception e) {
                    api.logging().logToError("Failed to store traffic item: " + e.getMessage());
                }
                return ResponseReceivedAction.continueWith(response);
            }
        });

        // Backfill existing proxy history in the background
        Thread backfillThread = new Thread(() -> {
            try {
                Thread.sleep(1500);
                int count = 0;
                for (var item : api.proxy().history()) {
                    try {
                        store.addHistoryItem(item);
                        count++;
                    } catch (Exception e) {
                        // Skip malformed items
                    }
                }
                api.logging().logToOutput("Burp REST Bridge: backfilled " + count + " proxy history items");
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        });
        backfillThread.setDaemon(true);
        backfillThread.setName("BurpRestBridge-Backfill");
        backfillThread.start();

        // Start the REST API server
        server = new ApiServer(api, store, 8090);
        server.start();

        api.logging().logToOutput("Burp REST Bridge started on http://127.0.0.1:8090");

        api.extension().registerUnloadingHandler(() -> {
            server.stop();
            api.logging().logToOutput("Burp REST Bridge stopped");
        });
    }
}
