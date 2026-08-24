// extension/src/hx/send/HttpReply.java
package hx.send;

/**
 * What one issuance produced.
 *
 * `connectionError` is not derivable from `status`, which is why it is a field
 * rather than a convention. Montoya answers a request that never got a
 * response with a response-less HttpRequestResponse rather than throwing, so
 * without this flag a dead host arrives as status 0 -- and Distress would count
 * status 0 as a perfectly good non-5xx reply. Spec s4 stops a run on FIVE
 * CONSECUTIVE connection errors; five status-0 replies are nothing at all.
 *
 * `raw` is the response exactly as it came off the wire, before redaction.
 * Sender redacts it; nothing else may hold onto it.
 *
 * THE MEASUREMENT, TAKEN. The question was whether `raw` can carry an INTERIM
 * response -- a `100 Continue` or a `103 Early Hints` -- ahead of the final
 * status line, and it was answered by driving a real headless Burp Suite
 * Community Edition 2026.7.3-52685 at a server that writes `103 Early Hints`
 * and then `200 OK` on one connection:
 *
 *   rr.hasResponse()                 true
 *   rr.response().statusCode()       103        <- the INTERIM head
 *   rr.response().toByteArray()      275 bytes, BOTH heads:
 *       "HTTP/1.1 103 Early Hints\r\nLink: ...\r\nSet-Cookie: interim=...\r\n"
 *       "\r\nHTTP/1.1 200 OK\r\n...Set-Cookie: session=...\r\n\r\n{...}"
 *
 * So Montoya parses the interim head as THE response and hands the rest back
 * as bytes. Two consequences, and both are load-bearing:
 *
 *   1. Redactor.redactResponse's 1xx branch is LIVE CODE on this path, not
 *      the dead branch it was thought to be. Task 4's second fix round -- a
 *      1xx is never the final response (RFC 9110 15.2), so its blank line
 *      does not end the scan -- is what keeps the FINAL head's Set-Cookie out
 *      of a content-addressed blob store. Task 4's ledger had recorded it as
 *      "not fixable from Redactor"; that was wrong, and the correction closed
 *      the last live credential-to-disk hole in the one item spec s7 says
 *      cannot be retrofitted.
 *   2. `status` cannot be reported as the transport gave it. Sender.finalStatus
 *      reads the final head out of `raw` when this field is a 1xx, because
 *      `status` is both the evidence line's status and the number Distress
 *      counts 5xx from -- and a CDN sending early hints in front of a failing
 *      origin would otherwise record nothing but 103s and never trip spec
 *      s4's auto-halt.
 */
public record HttpReply(int status, byte[] raw, long ms, boolean connectionError) { }
