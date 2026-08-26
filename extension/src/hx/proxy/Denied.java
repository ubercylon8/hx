// extension/src/hx/proxy/Denied.java
package hx.proxy;

/**
 * One request this extension refused at S4's second enforcement point.
 *
 * NO BODIES, deliberately. `bridge/server.py::_capture` reads `denial` and
 * `dropped` as frames that "describe something that produced no traffic, so
 * they arrive with an empty body" -- one body slot, not two -- and
 * `capture.py`'s denial arm writes a `denial` row with no blobs. Carrying
 * the refused request's bytes here would put a body on the wire nothing
 * reads and S7 never cleared for the store.
 *
 * WHAT A Denied IS NOT: proof that a denial row exists on the far side. A
 * Denied whose {@link Source} has no spelling is REFUSED by
 * {@link Capture#offer} and counted as a drop instead -- which is exactly
 * what happens to the request the gate refused BECAUSE it could not be
 * attributed. That is the honest reading and not an oversight: the bytes
 * still did not leave, and `hx.capture._run` would otherwise file the
 * refusal under the operator's run, which is the one thing
 * {@link Source#UNATTRIBUTED} exists to stop. CaptureTest's
 * `anUnattributedRecordIsRefusedAndCounted` pins the refusal for an
 * {@link Observed}; `aDeniedRecordWithNoSpellingIsRefusedTheSameWay` pins it
 * for this type.
 */
public record Denied(String method, String url, String errorClass,
                     String detail, Source source) implements Captured { }
