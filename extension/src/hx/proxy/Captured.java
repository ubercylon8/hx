// extension/src/hx/proxy/Captured.java
package hx.proxy;

/** One record on its way to the harness: an exchange that happened, or a
 *  denial that stopped one happening. Sealed, so `Capture.deliver`'s switch
 *  is exhaustive and a third kind is a COMPILE error rather than a record
 *  that silently reaches no arm. */
public sealed interface Captured permits Observed, Denied {
    Source source();
}
