package hx.proxy;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.proxy.http.*;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;

/**
 * A measuring extension that answers three questions about Burp's proxy and
 * writes what it saw to a file. It is NOT part of the shipped extension and
 * nothing in extension/src may depend on it.
 *
 * It lives under tests/ rather than under extension/src on purpose. It is a
 * second BurpExtension registering a second proxy request handler, and two
 * structural checks forbid that in the shipped tree: ChokepointTest requires
 * that only HxExtension.java imports burp.*, and Task 7 requires exactly one
 * registerRequestHandler. tests/integration/burp_fixture.py compiles this file
 * into a throwaway directory per run, against the Burp jar itself.
 *
 * It writes to a FILE rather than logging, because api.logging().logToError
 * goes to Burp's own extension log and not to stdout -- a fact that cost a
 * day on the previous branch when "no hx lines in burp.log" was read as "the
 * extension never ran".
 */
public class Probe implements BurpExtension {
    private static Path out;

    public void initialize(MontoyaApi api) {
        out = Path.of(System.getProperty("hx.probe.out", "/tmp/hx-probe.txt"));
        api.proxy().registerRequestHandler(new ProxyRequestHandler() {
            public ProxyRequestReceivedAction handleRequestReceived(InterceptedRequest r) {
                // Q1: every accessor that might name the listener. Reflection
                // rather than a compile-time call, so a method that does not
                // exist is a recorded ABSENCE rather than a build failure.
                StringBuilder sb = new StringBuilder("REQ id=" + r.messageId()
                        + " path=" + r.path());
                for (String name : new String[]{
                        "listenerInterface", "listenerPort", "sourceIpAddress",
                        "destinationIpAddress", "httpService"}) {
                    sb.append(' ').append(name).append('=');
                    try {
                        sb.append(r.getClass().getMethod(name).invoke(r));
                    } catch (NoSuchMethodException e) {
                        sb.append("<absent>");
                    } catch (Throwable e) {
                        // Unwrapped. A reflective call reports every failure as
                        // InvocationTargetException, and "it threw" is not a
                        // measurement -- WHAT it threw is. destinationIpAddress()
                        // exists on the same interface as listenerInterface() and
                        // is the accessor a future implementer would reach for
                        // next, so the record has to name its failure exactly.
                        Throwable c = (e instanceof java.lang.reflect.InvocationTargetException
                                       && e.getCause() != null) ? e.getCause() : e;
                        sb.append("<threw ").append(c.getClass().getName())
                          .append(": ").append(c.getMessage()).append('>');
                    }
                }
                write(sb.toString());

                // Q3: drop anything whose path says to, and record that we did.
                if (r.path().startsWith("/drop")) {
                    write("DROPPED id=" + r.messageId());
                    return ProxyRequestReceivedAction.drop();
                }
                return ProxyRequestReceivedAction.continueWith(r);
            }

            public ProxyRequestToBeSentAction handleRequestToBeSent(InterceptedRequest r) {
                return ProxyRequestToBeSentAction.continueWith(r);
            }
        });
        api.proxy().registerResponseHandler(new ProxyResponseHandler() {
            public ProxyResponseReceivedAction handleResponseReceived(InterceptedResponse r) {
                // Q2: does the id match the request's, and is it there at all?
                write("RESP id=" + r.messageId() + " status=" + r.statusCode()
                      + " reqpath=" + r.initiatingRequest().path());
                return ProxyResponseReceivedAction.continueWith(r);
            }

            public ProxyResponseToBeSentAction handleResponseToBeSent(InterceptedResponse r) {
                return ProxyResponseToBeSentAction.continueWith(r);
            }
        });
        write("PROBE READY");
    }

    private static synchronized void write(String line) {
        try {
            Files.writeString(out, line + "\n", StandardOpenOption.CREATE,
                              StandardOpenOption.APPEND);
        } catch (Exception e) {
            // A probe that cannot write has nothing to say; failing loudly
            // here would only obscure the run.
        }
    }
}
