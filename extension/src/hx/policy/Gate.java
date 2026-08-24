// extension/src/hx/policy/Gate.java
package hx.policy;

/**
 * The rate/budget half of the decision, behind one method.
 *
 * Policy consults a Gate rather than owning a Limiter so that the ordering of
 * the rules can be tested with a double that answers on command, and so that
 * Policy stays a pure function of its arguments. The real implementation is
 * hx.policy.Limiter.
 *
 * check() has a SIDE EFFECT -- Limiter spends a rate token and a budget slot
 * -- which is why Policy calls it last, and why nothing may call it on a
 * request an earlier rule has already refused.
 */
public interface Gate {
    Decision check(HxRequest req);
}
