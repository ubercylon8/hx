# What Burp's proxy actually does

**Measured against Burp Suite Community `2026.7.3`** (`burpsuite_desktop_v2026.7.3.jar`),
Montoya API as shipped in `burp-lab/probe/lib/montoya-api.jar`, on 2026-08-24,
JRE 26.0.2, headless, loopback only.

This document is one half of a deliverable. The other half is
`tests/integration/test_proxy_facts.py`, which re-measures all three answers
against a real Burp and fails if any of them changes. Q1's test reads this file
back, so the prose and the measurement cannot drift apart in silence.

**These are measurements, not decisions.** Nothing below was chosen; it is what
Burp did when asked. Two facts on the previous branch were designed around
wrongly because nobody measured them — `sendRequest()` returning when the
socket closes rather than when the response completes, and `toByteArray()`
carrying interim `1xx` heads so that `statusCode()` answered the interim status
and disarmed the auto-halt. Both survived review and were found by measuring.

## How to re-measure

```
.venv/bin/pytest tests/integration/test_proxy_facts.py -v -m integration
```

Every answer below is re-taken by that command against a real headless Burp,
in about 30 seconds. It launches a throwaway Burp with a private `$HOME`, two
loopback proxy listeners, and a probe extension that writes what it saw to a
file.

The probe's source is `tests/integration/probe/hx/proxy/Probe.java` and is
compiled per run into a temporary directory. It is deliberately **not** under
`extension/src`: it is a second `BurpExtension` registering a second proxy
request handler, and two structural checks forbid that in the shipped tree —
`ChokepointTest` requires that only `HxExtension.java` imports `burp.*`, and
Task 7 requires exactly one `registerRequestHandler`. It was written under
`extension/src` to take these measurements and removed from there in the same
task; keeping it beside the test is what stops this document from becoming a
claim nothing checks.

It writes to a **file** rather than to `api.logging()`, because
`logToOutput`/`logToError` reach Burp's own extension log and not the process
stdout. "No `hx` lines in `burp.log`" is not evidence an extension did not run
— that reading cost a day on the previous branch.

---

## Q1. Does `InterceptedRequest` expose which proxy listener it arrived on?

### Answer: YES — `listenerInterface()`, and it discriminates.

`InterceptedRequest.listenerInterface()` returns the listener's own bind
address as `host:port`:

```
REQ id=2 path=/api/orders     listenerInterface=127.0.0.1:42969 ...
REQ id=3 path=/account/logout listenerInterface=127.0.0.1:46007 ...
```

One Burp, two proxy listeners, the same target, the same client host — and the
two requests carry two different values, each naming the port it actually
arrived on. The port is the last `:`-separated field.

**Which fork Task 5 is on, in §4's terms.** §4 requires the operator/crawler
split to be a property of the **connection**, never of anything in the traffic.
`listenerInterface()` is exactly that: it is read off the accepting socket, a
client cannot set it, forge it, or influence it with any header, body or method,
and it is available on the request before any decision is taken. So:

> **`Source.forListenerPort` reads the port off `listenerInterface()`.**
> The fallback — a second `BridgeClient` on a second socket — is **not needed**
> and should not be built.

Two properties of the accessor that the fallback would have had and this does
not, stated so nobody has to rediscover them: the value is a *string* and must
be parsed (there is no `listenerPort()`, see below), and it names the
**interface Burp bound**, not the interface the client dialled. Those are the
same thing for a loopback-only listener, which is the only kind this project
opens.

### Every accessor that might name the connection

Measured by reflection, so that a method which does not exist is a recorded
absence rather than a compile error.

| accessor | verdict | what it returned |
| --- | --- | --- |
| `listenerInterface()` | present | `127.0.0.1:42969` — the listener's `host:port`. **This is the answer to Q1.** |
| `listenerPort()` | absent | No such method, on `InterceptedRequest` or anywhere in its hierarchy. The port must be parsed out of `listenerInterface()`. |
| `sourceIpAddress()` | present | `/127.0.0.1` — a `java.net.InetAddress`, so `toString()` carries the leading slash. The **client's** address, not the listener's; it cannot tell two listeners apart. |
| `destinationIpAddress()` | throws | `java.lang.UnsupportedOperationException: Not yet implemented`. **A trap.** It is declared on `InterceptedHttpMessage` alongside `listenerInterface()`, it compiles, and it raises on every call. |
| `httpService()` | present | `http://127.0.0.1:42797` — the **target**, not the listener. Identical for both listeners, so it answers a different question. |

`destinationIpAddress()` is the one to keep in mind. It is the accessor whose
*name* most suggests "the connection this arrived on", it is on the same
interface as the one that works, and the compiler will not stop anybody from
reaching for it.

### There is no API for creating a listener

`burp.api.montoya.proxy.Proxy` offers `enableIntercept`, `disableIntercept`,
`isInterceptEnabled`, `history`, `webSocketHistory`, `registerRequestHandler`,
`registerResponseHandler` and `registerWebSocketCreationHandler` — and nothing
that opens a port. The second listener a two-source split needs therefore comes
from a **project configuration file**, which Burp Community does accept:

```
--config-file=<file>
```

```json
{"proxy": {"request_listeners": [
  {"certificate_mode": "per_host", "listen_mode": "loopback_only",
   "listener_port": 42969, "running": true},
  {"certificate_mode": "per_host", "listen_mode": "loopback_only",
   "listener_port": 46007, "running": true}
]}}
```

Both listeners are named explicitly, including the first. A config naming only
the second would leave the first wherever Burp's default put it — see the port
warning below.

The list **replaces** Burp's defaults rather than adding to them. With the two
above configured, `ss -tlnp` against the Burp process shows exactly those two
proxy listeners and no 8080. Both bind `[::ffff:127.0.0.1]` — loopback only,
never `0.0.0.0`, which is what `listen_mode: loopback_only` buys and is not
optional: a proxy listener on `0.0.0.0` is an open relay on whatever network
the machine is attached to.

### Do not hard-code 8080

Burp Community's documented default proxy port is 8080, and on a developer
machine that is not a free port, it is whatever claimed it first. On this
machine 8080 is the local llama.cpp router (it answers a proxy-style
absolute-URI GET with `404` and a `Server: llama.cpp` header), 18080 is a node
service and 18081 is an agent. An earlier draft of the harness picked those
last two by hand: one returned a clean `421` and the other a clean `200`, both
recorded as Burp's proxy answering. Burp was never involved and the probe file
held nothing but `PROBE READY`.

A wrong port here does not fail, it **succeeds against the wrong process**. So
`burp_fixture.launch_probe` allocates free ports, writes them into the config
file it hands Burp, and `proxy_port()` reads them back from that same file; and
the fixture then sends one control request and requires it to appear in the
probe's own output before any test runs, because nothing about a successful
HTTP exchange proves the peer was Burp.

---

## Q2. Does `messageId()` correlate a request to its response?

### Answer: YES, including when responses arrive out of order.

Two requests were put in flight at once through one listener — the slow one
first, `/api/orders` half a second later — against a target that answers the
first one last. Verbatim from the probe's output for that run (which used
`ms=2000`; the standing test uses `ms=2500` for margin):

```
REQ  id=4 path=/slow?ms=2000
REQ  id=5 path=/api/orders
RESP id=5 status=200 reqpath=/api/orders
RESP id=4 status=200 reqpath=/slow?ms=2000
```

- Ids are assigned in **request** order (`4` before `5`).
- Responses arrive in **completion** order (`5` before `4`).
- Each response carries the id of **its own** request, and
  `initiatingRequest().path()` on that response agrees with the path of the
  request that holds the id.

So capture may pair the two halves of an exchange by `messageId()` and must not
pair them by arrival order. A sequential two-request check would have proved
nothing here: ids that merely count up match by accident when nothing overlaps,
which is why the test requires the out-of-order arrival before it believes the
pairing.

`messageId()` is an `int` and is per-Burp-instance, not per-listener: the ids
above were drawn from one sequence shared by both listeners.

---

## Q3. Does `drop()` actually prevent egress?

### Answer: YES to the target. NO to the client, and that is the complication.

`ProxyRequestReceivedAction.drop()` returned from `handleRequestReceived`
prevents the request reaching the target completely. The target server was
listening throughout and records every request it receives *before* answering
it; after a dropped `/drop/secret` its log holds nothing:

```
=== ALL TARGET HITS ===
  GET /health
  GET /health
  GET /slow    ms=2000
  GET /api/orders
```

Zero bytes. Not a truncated request, not a connection the target saw and
refused — the exchange never reached it.

### The client is told `200 OK`

The half that is not obvious, and that nothing may be built on top of. Burp
answers the dropping client itself, with its own page:

```
HTTP/1.1 200 OK
Connection: close
Cache-control: no-cache, no-store
Pragma: no-cache
X-Frame-Options: DENY
Content-Type: text/html; charset=utf-8
X-Content-Type-Options: nosniff

<html><head><title>Burp Suite</title>
...
```

1529 bytes, status **200**, on both a raw socket and `http.client`. A dropped
request and a delivered one are therefore **indistinguishable by status code**
from the client's side.

Consequences for Plan 4, since this is the second enforcement point:

- **Never read the client-visible status as evidence a request was blocked.**
  A test that dialled the proxy and asserted a non-2xx would pass whether or not
  the drop worked, and would go on passing if the drop stopped working. The only
  witness that separates the two is the far side receiving nothing.
- §4 requires denials to be recorded and never silent. The client cannot learn
  from the response that it was denied, so the `denial` row is not a duplicate of
  something the operator already sees in the browser — it is the *only* record.
- An operator browsing through the proxy will see a Burp page with a `200`
  where an out-of-scope request was dropped. That is not a failure.

---

## What was NOT measured

Stated rather than left to be discovered, because each of these is a place where
the answers above could fail to hold and nothing here would notice.

- **HTTPS / `CONNECT` tunnels.** Every measurement used plain HTTP through an
  absolute-URI proxy request. Whether `listenerInterface()` still names the
  accepting listener for a request read out of a TLS tunnel is **untested**, and
  it is the majority of real browsing. `tests/integration/target_server.py`
  serves no TLS, so measuring it needs a TLS target first. **Task 5 should
  re-measure Q1 over HTTPS before relying on the split for browser traffic.**
- **WebSocket traffic.** `registerWebSocketCreationHandler` was never exercised.
- **More than two listeners**, and listeners bound to anything other than
  `127.0.0.1`. `listen_mode` was `loopback_only` throughout — nothing in this
  project has ever sent a request off this machine, and a proxy listener on
  `0.0.0.0` is an open relay on whatever network the laptop is attached to.
- **Burp Professional.** Community only.
- **`drop()` from `handleRequestToBeSent`.** The drop measured here is from
  `handleRequestReceived`, which is the earlier of the two and the one Plan 4's
  gate uses.
