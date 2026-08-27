// extension/src/hx/proxy/Observed.java
package hx.proxy;

/**
 * One observed exchange, REDACTED, on its way to the harness.
 *
 * PACKAGE-PRIVATE, AND THAT IS THE WHOLE OF WHAT KEEPS ITS BYTES REDACTED.
 * A text scan cannot bound construction: `new Observed(` missed
 * `new hx.proxy.Observed(` and the widened `Observed(` missed `Observed::new`
 * -- both measured green, both leaking -- and a third needle would miss a
 * fourth spelling. The COMPILER bounds it instead: no code in another PACKAGE
 * can name this type by any spelling, so the only code that can build one is
 * code sitting next to {@link Recorder}, which is the class that redacts.
 * `RecorderTest.theCompilerBoundsConstruction` reads the compiled modifiers,
 * and adding `public` back here is the mutation that reopens it.
 *
 * WHAT PACKAGE-PRIVATE IS AND IS NOT. It is a COMPILE-TIME discipline over
 * this source tree, not a JVM boundary: anything that declares itself
 * {@code package hx.proxy;} gets in, which is precisely how `CaptureTest` and
 * `RecorderTest` build these records. That is the right bound for the defect
 * it closes -- someone in another package writing a fifth spelling of a
 * construction -- and it is not a claim that the type is unreachable.
 *
 * `status` AND `outcome` TRAVEL TOGETHER AND ARE BOTH THE SCAN'S. S5 makes
 * them one answer: `outcome='status_unreadable'` is legal only with
 * `status=599`, and the pair is what stops an unreadable head being filed as a
 * healthy sample. The proxy path shipped without the second half -- Montoya's
 * `statusCode()` passed through raw and a hardcoded `"ok"` written in
 * {@link Capture} -- so a `103 Early Hints` in front of a dead origin landed
 * `status=103, outcome=ok`, which is the pair S5 measured thirty of and the
 * one the send path needed five fix rounds to stop producing. Both fields are
 * now filled by {@link Recorder} from `hx.send.Sender.scanStatus`, the SAME
 * scan the send path uses, and there is no second implementation of it.
 *
 * `request` and `response` are post-redaction bytes. That is not a
 * convention: S7 says the blob store is content-addressed, so a credential
 * that reaches the hashing step is already unrecoverable, and the hashing
 * happens on the Python side. Redaction therefore has to be finished before
 * an Observed exists at all -- which is why the constructor takes bytes and
 * not a Montoya object.
 */
record Observed(String method, String url, int status, String outcome, long ms,
                byte[] request, byte[] response, Source source)
        implements Captured { }
