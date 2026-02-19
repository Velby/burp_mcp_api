import burp.api.montoya.proxy.ProxyHttpRequestResponse;

import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.stream.Collectors;

/**
 * Thread-safe in-memory store for captured HTTP traffic.
 * Holds at most MAX_ITEMS entries (oldest evicted first).
 * Most-recent items are returned first in searches (default).
 */
public class TrafficStore {

    private static final int MAX_ITEMS = 50_000;

    // Ordered oldest-first; access guarded by synchronized(items)
    private final LinkedList<TrafficItem> items = new LinkedList<>();
    // Fast lookup by id
    private final ConcurrentHashMap<Long, TrafficItem> byId = new ConcurrentHashMap<>();

    public void add(TrafficItem item) {
        synchronized (items) {
            if (items.size() >= MAX_ITEMS) {
                TrafficItem evicted = items.removeFirst();
                byId.remove(evicted.id);
            }
            items.addLast(item);
        }
        byId.put(item.id, item);
    }

    public void addHistoryItem(ProxyHttpRequestResponse histItem) {
        add(TrafficItem.fromHistoryItem(histItem));
    }

    public int size() {
        synchronized (items) {
            return items.size();
        }
    }

    public TrafficItem getById(long id) {
        return byId.get(id);
    }

    /**
     * Search traffic items with optional filters.
     *
     * @param host        substring match on hostname (case-insensitive)
     * @param method      exact match on HTTP method (case-insensitive)
     * @param statusStr   prefix match: "200" exact, "4" = 4xx, "20" = 200-209
     * @param search      substring search (case-insensitive)
     * @param searchIn    comma-separated parts to search: request, request_headers,
     *                    request_body, response, response_headers, response_body
     *                    (null/empty = search everywhere)
     * @param tool        exact match on tool name: PROXY, REPEATER, SCANNER, etc.
     * @param extExclude  comma-separated URL extensions to exclude, e.g. "js,css,png"
     * @param mimeInclude substring match on response Content-Type, e.g. "json", "html"
     * @param limit       max results
     * @param offset      skip first N results (pagination)
     * @param order       "asc" = oldest first, anything else = newest first (default)
     * @param mcpOnly  if true, only return items with a claude_tag (sent by Claude)
     */
    public List<TrafficItem> search(String host, String method, String statusStr,
                                    String search, String searchIn, String tool,
                                    String extExclude, String mimeInclude,
                                    int limit, int offset, String order, boolean mcpOnly) {
        Set<String> searchInParts = parseCsvSet(searchIn);
        Set<String> extExcludeSet = parseCsvSetLower(extExclude);
        String mimeFilter = mimeInclude != null && !mimeInclude.isEmpty()
                ? mimeInclude.toLowerCase(Locale.ROOT) : null;
        boolean ascending = "asc".equalsIgnoreCase(order);

        List<TrafficItem> snapshot;
        synchronized (items) {
            snapshot = new ArrayList<>(items.size());
            if (ascending) {
                snapshot.addAll(items);                     // oldest first
            } else {
                var it = items.descendingIterator();
                while (it.hasNext()) snapshot.add(it.next()); // newest first (default)
            }
        }

        return snapshot.stream()
                .filter(i -> !mcpOnly         || i.mcpTag != null)
                .filter(i -> isBlank(host)       || i.host.toLowerCase(Locale.ROOT).contains(host.toLowerCase(Locale.ROOT)))
                .filter(i -> isBlank(method)     || method.equalsIgnoreCase(i.method))
                .filter(i -> isBlank(statusStr)  || matchesStatus(i.statusCode, statusStr))
                .filter(i -> isBlank(tool)       || tool.equalsIgnoreCase(i.tool))
                .filter(i -> extExcludeSet.isEmpty() || !extExcludeSet.contains(i.getUrlExtension()))
                .filter(i -> mimeFilter == null  || i.getContentType().contains(mimeFilter))
                .filter(i -> isBlank(search)     || (searchInParts.isEmpty()
                        ? containsSearchAll(i, search)
                        : i.containsSearchIn(search, searchInParts)))
                .skip(offset)
                .limit(limit)
                .collect(Collectors.toList());
    }

    /** Return the most recent item matching the given tool, or null. */
    public TrafficItem getLatestByTool(String tool) {
        synchronized (items) {
            var it = items.descendingIterator();
            while (it.hasNext()) {
                TrafficItem item = it.next();
                if (tool.equalsIgnoreCase(item.tool)) return item;
            }
        }
        return null;
    }

    /** Sorted list of unique hostnames seen in captured traffic. */
    public List<String> getHosts() {
        Set<String> seen = new LinkedHashSet<>();
        synchronized (items) {
            var it = items.descendingIterator();
            while (it.hasNext()) seen.add(it.next().host);
        }
        List<String> list = new ArrayList<>(seen);
        Collections.sort(list);
        return list;
    }

    // ── helpers ───────────────────────────────────────────────────────────────

    private static boolean isBlank(String s) {
        return s == null || s.isEmpty();
    }

    private static boolean matchesStatus(int code, String filter) {
        return String.valueOf(code).startsWith(filter);
    }

    private static boolean containsSearchAll(TrafficItem item, String search) {
        String needle = search.toLowerCase(Locale.ROOT);
        if (item.path.toLowerCase(Locale.ROOT).contains(needle)) return true;
        if (item.host.toLowerCase(Locale.ROOT).contains(needle)) return true;
        if (item.requestBytes.length > 0) {
            if (new String(item.requestBytes, java.nio.charset.StandardCharsets.ISO_8859_1)
                    .toLowerCase(Locale.ROOT).contains(needle)) return true;
        }
        if (item.responseBytes.length > 0) {
            if (new String(item.responseBytes, java.nio.charset.StandardCharsets.ISO_8859_1)
                    .toLowerCase(Locale.ROOT).contains(needle)) return true;
        }
        return false;
    }

    private static Set<String> parseCsvSet(String csv) {
        if (csv == null || csv.isEmpty()) return Set.of();
        Set<String> set = new LinkedHashSet<>();
        for (String s : csv.split(",")) {
            String t = s.trim();
            if (!t.isEmpty()) set.add(t);
        }
        return set;
    }

    private static Set<String> parseCsvSetLower(String csv) {
        if (csv == null || csv.isEmpty()) return Set.of();
        Set<String> set = new LinkedHashSet<>();
        for (String s : csv.split(",")) {
            String t = s.trim().toLowerCase(Locale.ROOT);
            if (!t.isEmpty()) set.add(t);
        }
        return set;
    }
}
