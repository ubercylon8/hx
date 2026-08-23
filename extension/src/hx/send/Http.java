// extension/src/hx/send/Http.java
package hx.send;

import hx.policy.HxRequest;

import java.io.IOException;

/**
 * The extension's entire reach to the network, in one method.
 *
 * It is an interface so that Sender can be driven by a fake that RECORDS ITS
 * CALLS. Every denial in this package is asserted as "the fake Http was called
 * zero times", not as "an error map came back" -- a Sender that called Montoya
 * directly could only ever be tested for the second, and spec s4 is about the
 * first.
 *
 * The single implementation that touches Burp is built in HxExtension, which
 * is also the only file in extension/src allowed to name burp.* at all.
 * ChokepointTest counts both facts.
 */
public interface Http {

    /**
     * Issue {@code req} and return what came back.
     *
     * @param deadlineUs absolute microseconds since epoch, straight from the
     *   send frame. An implementation should cap its own wait at the time
     *   remaining, but that is an optimisation: Sender re-reads the clock after
     *   this returns and answers `timeout` on its own account, so the deadline
     *   holds even if the transport ignores it.
     * @throws IOException the request could not be issued at all. Sender turns
     *   this into `transport_error` and feeds it to Distress as a connection
     *   error, which is one of the three auto-halt conditions in spec s4.
     */
    HttpReply send(HxRequest req, long deadlineUs) throws IOException;
}
