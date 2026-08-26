// extension/src/hx/proxy/Observed.java
package hx.proxy;

/**
 * One observed exchange, REDACTED, on its way to the harness.
 *
 * `request` and `response` are post-redaction bytes. That is not a
 * convention: S7 says the blob store is content-addressed, so a credential
 * that reaches the hashing step is already unrecoverable, and the hashing
 * happens on the Python side. Redaction therefore has to be finished before
 * an Observed exists at all -- which is why the constructor takes bytes and
 * not a Montoya object.
 */
public record Observed(String method, String url, int status, long ms,
                       byte[] request, byte[] response, Source source)
        implements Captured { }
