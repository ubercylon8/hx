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
     * Issue {@code wire} to the service {@code req} names, and return what came
     * back.
     *
     * THE BYTES ARE A PARAMETER, and they used to be built here from {@code
     * req} by the one implementation. Identity injection is why they moved:
     * {@code Sender} composes the request AFTER the gate, writes the identity
     * header into it and registers the byte range of the credential with the
     * {@link Redactor.Injected} for THAT array -- and {@code Injected} holds
     * its array by identity, so an implementation that re-serialised {@code
     * req} would issue a third array that no range set names. One
     * serialisation, in the class that decided about it, is also what makes
     * the exact bytes assertable against a fake.
     *
     * {@code req} still comes with them because the DESTINATION is not in the
     * bytes: an implementation reads {@code host()}, {@link Sender#portOf} and
     * {@link Sender#secureOf} off it to open the connection, exactly as before.
     * The two DESCRIBE THE SAME REQUEST -- {@code Sender} serialised one from
     * the other and hands both on, so {@code req} carries any injected header
     * too -- and an implementation must still not re-derive the payload from
     * it, because an equal-looking array is not the array the ranges were
     * measured from.
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
    HttpReply send(HxRequest req, byte[] wire, long deadlineUs) throws IOException;
}
