// extension/src/hx/policy/HxRequest.java
package hx.policy;

import java.util.List;
import java.util.Map;

/**
 * One request, already split into the parts the rules ask about. This is what
 * Policy decides about and what Sender puts on the wire, so the two are never
 * reasoning about different requests.
 *
 * `url` is the whole thing -- scheme, authority, path and query -- and `host`
 * is the name Burp actually connects to. They are both here because they can
 * disagree: `host` comes from the send frame's `target_host` and `url` is
 * built from it, so a `target_host` of "app.example.test:8443" or
 * "app.example.test@evil.example.test" produces a url whose authority is not
 * the host at all. Policy checks that they agree before it matches anything;
 * see Policy.scopeOf.
 *
 * `body` is a byte[], so the record's generated equals() and hashCode()
 * compare it by IDENTITY. Nothing in this project compares HxRequests or uses
 * one as a map key, and nothing should start: a value-looking type that is not
 * a value is worth knowing about before you rely on it.
 */
public record HxRequest(String method, String url, String host, String path,
                        String query, Map<String, List<String>> headers, byte[] body) {

    /**
     * IllegalArgumentException rather than a late NullPointerException: the one
     * caller in production is Sender.parse, whose try/catch turns exactly this
     * type into error class `bad_frame`. A field that arrives null there is a
     * malformed send frame, and it should be answered as one rather than
     * unwinding out of the send arm as an unhandled exception.
     */
    public HxRequest {
        if (method == null) throw new IllegalArgumentException("method is null");
        if (url == null) throw new IllegalArgumentException("url is null");
        if (host == null) throw new IllegalArgumentException("host is null");
        if (path == null) throw new IllegalArgumentException("path is null");
        if (query == null) throw new IllegalArgumentException("query is null");
        if (headers == null) throw new IllegalArgumentException("headers is null");
        if (body == null) throw new IllegalArgumentException("body is null");
    }

    /**
     * The origin-form request target: the path, plus "?" and the query when
     * there is one. What the dangerous-path denylist matches against, because
     * a logout is as often `/index.php?action=logout` as it is `/logout`.
     */
    public String target() {
        return query.isEmpty() ? path : path + "?" + query;
    }
}
