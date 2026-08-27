# What Burp's proxy actually does

**Measured against Burp Suite Community `2026.7.3`** (`burpsuite_desktop_v2026.7.3.jar`),
on 2026-08-24, JRE 26.0.2, headless, loopback only.

The probe is compiled against **the Burp jar itself**, not against the
standalone `burp-lab/probe/lib/montoya-api.jar`: Burp ships the whole Montoya
API inside `burpsuite_desktop_v2026.7.3.jar` (997 entries under
`burp/api/montoya/`), so the measurement adds no prerequisite that
`-m integration` did not already have. That standalone jar is
`Implementation-Version: 2025.10` — older — and it is what `extension/build.sh`
compiles the shipped extension against. For the accessors below it makes no
difference, and that is measured rather than assumed:
`InterceptedRequest.class` and `InterceptedHttpMessage.class` are byte-identical
between the two jars (`sha256` match on both). An earlier version of this line
credited the measurements to the standalone jar and contradicted the fixture.

This document is one half of a deliverable. The other half is
`tests/integration/test_proxy_facts.py`, which re-measures Q1, Q2 and Q3
against a real Burp and fails if any of them changes. (Q4 is the exception and
says so in its own section: re-taking it needs a probe patch that must not
ship. Q5 is re-measured too, but from
`tests/integration/test_proxy_capture.py` rather than from here — it needs a
target that stops answering mid-test, which is the standing rig's target and
not the probe's.) Two of those tests read this file back — Q1's checks the accessor table, Q3's checks the status and byte
count Burp answers a dropped client with — so the prose and the measurement
cannot drift apart in silence. Everything outside those two readbacks is prose
that nothing enforces, and is marked as such where it matters.

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

**Deleting it is a test failure, not a skip.** Task 1's brief ends with a step
that says "delete the probe", and that step means *delete it from
`extension/src`* — where it breaks `ChokepointTest` and Task 7 — and not from
here. Removing `tests/integration/probe/` used to produce `3 skipped in 0.03s`
with no error and no diagnostic, while the default run's summary line announces
*deselected* integration tests and never mentions skipped ones. A missing Burp
jar or JDK still skips; those are facts about a machine. A file this repository
ships is not.

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
| `sourceIpAddress()` | present | `/127.0.0.1` — a `java.net.InetAddress`, so `toString()` carries the leading slash. The **client's** address, not the listener's; it cannot tell two listeners apart. Its `toString()` is **not a stable shape**: the same client through a `CONNECT` tunnel rendered as `localhost/127.0.0.1`, hostname included. Do not parse it. |
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

The list **replaces** Burp's defaults rather than adding to them: no 8080
appears. But it does not account for every socket Burp opens. With the two
above configured, `ss -ltnp` against the Burp process shows **three** listening
sockets, not two (a different run from the Q1 excerpt above — the ports are
allocated free per run and are never the same twice):

```
LISTEN [::ffff:127.0.0.1]:45327   users:(("java",pid=...))   <- configured
LISTEN [::ffff:127.0.0.1]:46387   users:(("java",pid=...))   <- configured
LISTEN [::ffff:127.0.0.1]:43719   users:(("java",pid=...))   <- nobody asked for this
```

All three bind `[::ffff:127.0.0.1]` — loopback, never `0.0.0.0`.

### Burp's third listener

The extra one is Burp's own, on an ephemeral port that changes every run, and
it is **not** a second proxy. Measured directly against it:

| sent to it | it answered |
| --- | --- |
| absolute-URI `GET http://target/from-third` | `HTTP/1.1 204 No Content` (27 bytes) |
| origin-form `GET /plain` | nothing; the connection closes |
| `CONNECT target:port` | `HTTP/1.1 200 Connection established` |
| a `GET` inside that tunnel | `HTTP/1.1 204 No Content` |

The target server's log stayed **empty** throughout and the probe's own handler
never saw any of it. It accepts, answers `204`, and forwards nothing. So it is
not an enforcement hole — but it is on loopback, and any check that all of this
Burp's listeners are on loopback has to expect it rather than fail on it.

### `loopback_only` is checked, not assumed

`listen_mode: loopback_only` is what keeps the two configured listeners off the
network, and it is **not optional**: a proxy listener on `0.0.0.0` is an open
forward relay on whatever network the machine is attached to, for as long as the
run lasts.

Until `burp_fixture.not_loopback_only()` existed, that was asserted in three
places — this paragraph among them — and checked by nothing. Changing that one
string to `all_interfaces` left the suite reporting `3 passed in 38.03s` while
`ss` showed the two proxy listeners bound to `*:34777` and `*:38399` —
reproduced, on this machine. The
fixture in `test_proxy_facts.py` now reads `ss -ltnpH` for the Burp pid after
`PROBE READY` and fails naming the address it found; the same mutation now
reports:

```
burp pid 3827568 is listening on ['*:44741', '*:33527'], which is not loopback.
```

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

The ids are **not contiguous**. Three requests sent through `CONNECT` tunnels
reached the handler as `5`, `7` and `9`; `4`, `6` and `8` were never delivered
to it. The `CONNECT` requests themselves are the obvious candidate for the
missing ids, but that was not confirmed — what is measured is only that the
sequence has gaps, so nothing may infer "the next request" from `id + 1`.

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

The page is static — two drops of very different path lengths measured 1529
bytes each, and it echoes nothing of the request — so that number is a constant
rather than a fingerprint of one URL.

> **Both numbers above are read back by `test_q3_drop_means_the_target_receives_nothing`,**
> which measures the real response and then requires this document to record the
> same status and the same byte count on one line, and requires the word
> *indistinguishable* to still appear. This section used to be deletable in
> full with that test still green — reproduced, both directions. Editing it is
> fine; deleting the finding is what goes red.

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

## Q4. Does `drop()` from `handleRequestToBeSent` also prevent egress?

### Answer: NO. It prevents nothing. The two callbacks' `drop()` are not interchangeable.

`ProxyRequestHandler` has two callbacks and Montoya documents their two `drop()`
actions identically. Q3 measured the first. This measures the second, and the
answer is the opposite one.

The probe was patched to drop at `handleRequestToBeSent` on a `/latedrop` path,
leaving its existing `/drop` behaviour at `handleRequestReceived` untouched, so
both actions could be taken in one Burp against one target. The patch was
reverted afterwards; it is not in the shipped probe. Reproducing it is four
lines — see "How to re-take this one" below.

```
control:            HTTP/1.0 200 OK          157 bytes   target hits: [('GET','/health')]
latedrop response:  HTTP/1.0 404 Not Found   178 bytes   target hits delta: 1
earlydrop response: HTTP/1.1 200 OK         1529 bytes   target hits delta: 0
```

Read that middle line carefully. `HTTP/1.0` and a **404** is the *target
server's own answer* — this target speaks HTTP/1.0 and answers 404 for an
unrouted path. Burp's drop page is `HTTP/1.1 200` in 1529 bytes and is on the
third line. So the late-dropped request was **delivered, answered, and the
answer was handed back to the client**.

The probe's own log shows the same thing from inside the JVM:

```
TBS id=1 path=/latedrop/secret
LATEDROPPED id=1 action=DROP class=jdk.proxy2.$Proxy124
RESP id=1 status=404 reqpath=/latedrop/secret
DROPPED id=2
```

`action=DROP` is printed off the returned object's own `action()` accessor, so
this is not a case of building the wrong action: the extension asked for a drop,
Burp acknowledged a drop, and forwarded the request. A response handler then ran
on the target's real 404, which is the second half of the same finding — the
exchange completes normally in every respect.

The last line is `/drop/secret` through `handleRequestReceived` in the same run:
zero hits, `DROPPED` logged, and no `TBS` line for that message id at all.

### A request dropped at the first callback never reaches the second

Visible in the log above and worth stating separately, because a design can rest
on it: message id 2 was dropped at `handleRequestReceived` and produced no `TBS`
line. So reaching `handleRequestToBeSent` means the first callback **allowed**
the request, and a `deny` answer at the second callback is by construction a
*disagreement* with the first — which is to say an edit in the Intercept tab
that sits between them.

### Consequences, and what the extension does now

- **The proxy has ONE enforcement point, not two callbacks' worth.**
  `handleRequestReceived` enforces. `handleRequestToBeSent` cannot. §4's count
  of two enforcement points — the send path and the proxy request handler — is
  unaffected; what is affected is a stronger claim that was never §4's: that a
  request edited *after* the first decision is re-checked. It is not, and on
  this Burp it cannot be.
- **The hole is real and it is the Intercept tab.** An operator can rewrite a
  request there, host included, after `handleRequestReceived` has approved the
  original. Nothing in the JVM can stop the edited request leaving.
- **`HxExtension.handleRequestToBeSent` no longer tries.** It used to return
  `drop()` and write a `denial` row. That row was *fabricated evidence in the
  dangerous direction*: hx recorded a refusal for a request that reached the
  client's system, and — because the refusal branch also took the `pending`
  entry — discarded the clock and source of the exchange that actually happened,
  so the response was charged to `countLost`. The callback now asks
  `decideScopeOnly`, logs loudly through `api.logging().logToError` when the
  answer disagrees with the first callback's, and returns `continueWith`.
- **The escape is still recorded, and that is the honest record.** An edited
  out-of-scope request goes out, is answered, and reaches
  `handleResponseReceived` like any other — so it lands as an `exchange` row
  whose `url` is outside `scope.include`. Nothing had to be added to *have* that
  evidence; a query for exchanges outside the scope patterns finds it.
- **Rewriting the request to something harmless was considered and refused.** It
  would fabricate traffic the operator never sent, which is worse than recording
  the escape.

### How to re-take this one

Unlike Q1–Q3 there is no test that re-measures this, and the reason is a
trade rather than an oversight: measuring it needs a probe that drops at the
second callback, and the shipped probe deliberately does not — `test_proxy_facts`
would then be measuring an action no shipped code takes. What *is* pinned, in
`ChokepointTest.theSecondCallbackObservesAndCannotRefuse`, is the consequence:
`ProxyRequestToBeSentAction.drop(` must appear **zero** times in
`HxExtension.java`, the scope question must still be asked, and its answer must
be logged between the asking and the pass-through. That is the check that stops
the refusal being put back by a reader who finds a pass-through where a scope
check used to be.

To re-measure against a future Burp, patch
`tests/integration/probe/hx/proxy/Probe.java`'s `handleRequestToBeSent`:

```java
public ProxyRequestToBeSentAction handleRequestToBeSent(InterceptedRequest r) {
    write("TBS id=" + r.messageId() + " path=" + r.path());
    if (r.path().startsWith("/latedrop")) {
        ProxyRequestToBeSentAction a = ProxyRequestToBeSentAction.drop();
        write("LATEDROPPED id=" + r.messageId() + " action=" + a.action());
        return a;
    }
    return ProxyRequestToBeSentAction.continueWith(r);
}
```

then drive `/latedrop/secret` and `/drop/secret` through one probe and read the
target's log. **Revert the patch afterwards** — a probe that drops at the second
callback would make `test_proxy_facts.py`'s Q3 measure two different actions.

If a future Burp answers YES here, that is a better world and it is a new
measurement, not a bug fix: the refusal could go back, and this section and
`HxExtension.handleRequestToBeSent` would have to change together.

---

## Q5. What happens when an allowed request cannot connect?

### Answer: NOTHING REACHES `hx`. No callback, no row, no drop.

**Measured 2026-08-26**, same Burp, through the standing rig rather than the
probe: an in-scope destination that the gate ALLOWS and that then refuses the
connection (the target server stopped mid-test, so the port is closed while the
scope rule still matches).

| What | Result |
|---|---|
| The client is answered | `HTTP/1.1 200 OK`, ~1535 bytes, `<title>Burp Suite</title>` |
| `exchange` rows | **none** |
| `denial` rows | **none** |
| `run.dropped_total` | **unmoved** |
| `BridgeServer.exchange_errors` | 0 — nothing failed; nothing was attempted |

The client-side answer is the same SHAPE as a dropped request (Q3, ~1529 bytes,
identical head). **A client cannot tell "hx refused this" from "nothing
answered"**, which is one more reason Q3's byte count is the only thing
separating them and why nothing in this project reads the client's response to
decide what happened.

### `handleResponseReceived` did not run — inferred, and here is the inference

Not observed directly; argued from the rows, because both halves are checkable.
Had the callback run and FOUND its `Pending` entry there would be an exchange
row. Had it run and MISSED, `Capture.countLost` would have moved
`dropped_total`. Neither moved, so the callback did not run for that message —
and the `Pending` entry is still in the map, waiting to be evicted by capacity
pressure. `Pending.evicted()` has no reader outside its own test.

### There is no failure callback to register

Measured off `montoya-api.jar` (2025-09-23), the jar `extension/build.sh`
compiles against, with `javap`:

```
ProxyRequestHandler   handleRequestReceived, handleRequestToBeSent          (2)
ProxyResponseHandler  handleResponseReceived, handleResponseToBeSent        (2)
HttpHandler           handleHttpRequestToBeSent, handleHttpResponseReceived (2)
```

Six methods, all response-shaped. None is a failure or timeout notification.
**There is nothing to register**, so this gap cannot be closed by finding the
right callback.

### The one facility that might close it, and what is still unmeasured

`Proxy.history()` returns `List<ProxyHttpRequestResponse>`, and that type has
`hasResponse()`, `id()`, `listenerPort()` and `timingData()`. It is a POLL, not
a callback. **Two things about it are unmeasured and both must be answered
before anything is built on it:**

1. does Burp enter a request that never connected into proxy history **at
   all**, or only requests that got a response?
2. does anything there separate "no response **yet**" from "no response
   **ever**"? A long-poll, an SSE stream and a WebSocket upgrade are all
   legitimately answerless for minutes.

Both are `test_proxy_facts.py`-shaped questions and neither has been asked.
Until they are, the alternatives are a time-based sweep of `Pending` — which
must pick one of §5's four transport outcomes with nothing to distinguish them,
and must pick a duration that a long-poll would fail — or nothing. This project
has twice refused to record a guess as a fact (`transport_error` has no row;
the 599 sentinel needed its own outcome), so it is nothing, for now.

### Where this is pinned

`tests/integration/test_proxy_capture.py::test_an_allowed_request_that_cannot_
connect_leaves_no_trace_at_all`. It asserts the GAP: if it goes red, either a
Burp upgrade changed the behaviour or someone closed it, and both are worth
finding out about deliberately rather than in a report.

---

## Q1 and Q3 over HTTPS, through a `CONNECT` tunnel

An earlier version of this document listed HTTPS as unmeasured and told Task 5
to re-measure Q1 before relying on the split for browser traffic. It has since
been measured, twice independently — by this task's review and again here. Both
answers hold, and Task 5 does not need to re-derive them.

The rig, a throwaway script rather than anything in the suite (see the note at
the end of this section): a self-signed TLS server on loopback in place of the
plain-HTTP target, and a client that sends `CONNECT 127.0.0.1:<tls-port>`, wraps
the tunnel in TLS (Burp MITMs it with its own per-host certificate) and sends
the request inside. The TLS server counts **TCP accepts** and completed
handshakes, so "the target received nothing" is a claim about the socket rather
than about HTTP.

### Q1 holds. `listenerInterface()` still discriminates.

Two tunnelled requests, one through each listener:

```
REQ id=5 path=/tunnel/one listenerInterface=127.0.0.1:40421 ... httpService=https://127.0.0.1:41431
REQ id=7 path=/tunnel/two listenerInterface=127.0.0.1:41543 ... httpService=https://127.0.0.1:41431
```

Two listeners, two values, each naming the port the tunnel was opened on —
exactly as for plain HTTP. `httpService()` reports the `https://` scheme, so the
handler can also tell that the request came out of a tunnel. **The
operator/crawler split is not broken for browser traffic.**

### Q3 holds, and more strongly than over plain HTTP.

`drop()` returned for a request read out of an established tunnel:

```
REQ id=9 path=/drop/in-a-tunnel listenerInterface=127.0.0.1:40421 ... httpService=https://127.0.0.1:41431
DROPPED id=9
```

The TLS target's counters were `accepts=3, handshakes=3` before the drop and
`accepts=3, handshakes=3` after it. **Zero TCP accepts, therefore zero TLS
handshakes and no SNI** — Burp does not dial the target before the handler has
decided. Over plain HTTP the evidence is "no HTTP request arrived"; here it is
"no connection was ever made".

The client-side half is the same trap: inside the tunnel the dropping client
received Burp's own `HTTP/1.1 200 OK` error page. Its head is identical to the
plain-HTTP one above, down to `X-Content-Type-Options: nosniff`; the total
length was not compared, so treat 1529 as a plain-HTTP measurement.

**Not covered by the standing test.** `tests/integration/target_server.py`
serves no TLS, so `test_proxy_facts.py` re-measures Q1 and Q3 over plain HTTP
only. These two answers are recorded here and are **not** protected against a
future Burp changing them. If Task 5 or later comes to depend on tunnelled
behaviour specifically, that dependency needs a TLS target in the suite first.

---

## What was NOT measured

Stated rather than left to be discovered, because each of these is a place where
the answers above could fail to hold and nothing here would notice.

- **WebSocket traffic.** `registerWebSocketCreationHandler` was never exercised.
- **More than two configured listeners**, and listeners bound to anything other
  than `127.0.0.1`. `listen_mode` was `loopback_only` throughout — nothing in
  this project has ever sent a request off this machine — and that is now
  enforced rather than intended; see "`loopback_only` is checked, not assumed".
- **Burp Professional.** Community only.
- ~~**`drop()` from `handleRequestToBeSent`.**~~ **Measured — see Q4.** It was
  listed here on the reasoning that the drop measured in Q3 is from
  `handleRequestReceived`, "which is the earlier of the two and the one Plan 4's
  gate uses". By the time it was measured, Plan 4's gate was using both, and the
  later one does not work. Left in place struck through rather than deleted: the
  entry that was hardest to justify keeping on this list is the one that turned
  out to matter, and a reader deciding what to measure next should see that.
- **What Burp's third listener is for.** Its behaviour is measured above; why it
  exists is not. Nothing in Plan 4 sends anything to it.
- **`Proxy.history()` on a request that never connected.** Named in Q5 as the
  one facility that might close the gap Q5 measures, and named here because it
  is the measurement somebody will need before building on it: whether a failed
  request appears in proxy history at all, and whether anything there separates
  "no response yet" from "no response ever". Neither has been asked.
- **A DNS failure and a TLS failure specifically.** Q5 measured a REFUSED
  CONNECTION. §5's vocabulary has three transport outcomes and this
  measurement produced evidence for none of them, so "all three behave alike"
  is an assumption and is written here rather than in Q5's answer.
