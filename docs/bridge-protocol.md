# hx bridge wire protocol v1

## Framing

    [4-byte big-endian unsigned length][header bytes][body bytes]

`length` counts header + body. It is attacker-influenced: reject anything
above MAX_FRAME (64 MiB) before allocating.

The header is a **flat** JSON object, UTF-8, terminated by a newline (`\n`).
Everything after that newline, to the end of the frame, is the body.

Flat means: string keys, and values that are only string, integer, boolean or
null. No nested objects, no arrays. This keeps the Java parser small enough to
be obviously correct. Structured payloads travel in the body.

## Header fields

Every frame:
  v          integer  protocol version, currently 1
  t          string   frame type

Request/response frames (`send`, `result`, `error`, `configure`, `configured`):
  id         integer  monotonic, set by the sender of the request
  deadline_us integer absolute microseconds; the receiver abandons work past it

## Two things a second implementation must match

**Key order is preserved on the wire.** The header is written in insertion
order, and the golden vectors compare exact bytes. A writer using an unordered
map produces a semantically identical header with different bytes and fails the
vector comparison. Parsing is order-independent; only the byte comparison cares.

**Header integers are 64-bit signed.** `deadline_us` is absolute microseconds
since epoch -- about 1.79e15 today, which overflows a 32-bit integer by roughly
six orders of magnitude. Parse header numbers into a 64-bit type. Floats and
exponents are not valid header numbers.

**Non-ASCII header values are raw UTF-8, not `\uXXXX` escapes.** Only the
characters JSON requires are escaped: `"` `\\` and the control characters.

## Frame types

  burp -> py   hello       {v,t,ext_version,pid,burp_version,instance_id,engagement_id}
  py -> burp   configure   {v,t,id,deadline_us,engagement_id,scope_sha256,profile}
                           body: config lines (below)
  burp -> py   configured  {v,t,id,config_epoch}
  py -> burp   send        {v,t,id,deadline_us,engagement_id,identity_id,target_host,target_port,tls}
                           body: raw HTTP request bytes
  burp -> py   result      {v,t,id,status,bytes,ms,outcome,config_epoch}
                           body: redacted raw HTTP response bytes
  burp -> py   error       {v,t,id,class,detail}
                           plus retry_after_us, on rate_limited only
  burp -> py   halted      {v,t,reason,host,window}   unsolicited; no id.
  burp -> py   exchange    {v,t,...}   unsolicited; no id. Defined in a later plan.
  py -> burp   halt        {v,t,reason}
  py -> burp   resume      {v,t}

`send.engagement_id` is required. The extension serves exactly one engagement
and refuses a send that names another with class `engagement_mismatch`, before
the request is decided about at all: one client's bytes must never reach
another client's report, and two harnesses sharing a Burp is the way that
happens.

`result.config_epoch` is the epoch of the Authorisation the request was
decided under, read in one shot with the scope that epoch granted. It is the
answer to "what was in scope when request X was issued", and it has to come
from the same read as the decision or it is not an answer at all.

`exchange_id` is NOT on this frame. It is a store row id, assigned by
`record_exchange()` on the Python side; the extension has none to give.

`result.status` is the status of the FINAL response, which is not always the
one the transport reported. MEASURED against Burp Suite Community Edition
2026.7.3-52685 on a 103-then-200 exchange: `statusCode()` answered **103** and
`toByteArray()` carried BOTH heads. A peer may put interim `1xx` heads in front
of its real answer, so a second implementation must read the last status line
out of the response bytes rather than trusting its HTTP client's parse of the
first. Reporting the interim status puts a wrong number on the evidence line
and -- much worse -- feeds a healthy sample to the auto-halt, so a CDN sending
early hints in front of a failing origin would hold a 0% 5xx rate forever. The
scan is bounded (8 heads, the last of which must be the final one). Any scan
that does not reach a final status line reports **599** rather than the interim
status: an unreadable status must not read as a healthy one. That is the
budget running out, and equally the bytes running out -- truncated mid-status-
line, truncated after the interim head's blank line, or a line the scan cannot
read. "The bytes ran out, so nothing was hidden" is a statement about the bytes;
a 1xx is still not the final response when the connection dies. The truncated
ending is not the exotic one of the two: it is what a CDN's `103 Early Hints`
in front of a dead origin looks like, and it was measured against Burp Suite
Community Edition 2026.7.3 -- `hasResponse()` is **true**, `statusCode()`
answers the interim **103**, and `toByteArray()` carries the interim head and
nothing else. A second implementation that reports that 103 hands its own
auto-halt a healthy sample for every request against a dead origin.

`result.outcome` is `ok`, or `status_unreadable` when that 599 is the
extension's own answer rather than the peer's. The two need telling apart and
`status` cannot do it: 599 is **not a reserved code** -- it is in unofficial use
for connect timeouts, which is exactly the class of peer (a proxy in front of an
origin) that also emits early hints -- so `{status: 599}` alone is the same
frame whether the exchange succeeded with a 200 behind eight interim heads or
the peer genuinely answered 599. Read one way it indexes a successful exchange
as a 5xx while the redacted bytes on that same frame say `HTTP/1.1 200 OK`; read
the other way it launders a real proxy 599 into "status unknown". `status`
stays 599 in both cases regardless -- the auto-halt in §4 must keep counting an
unreadable status as an error, and that property must not come to depend on a
consumer reading a second field.

Note for a consumer that persists these: the store's `exchange.outcome` takes
this value UNCHANGED. The wire value and the column value are deliberately the
same string, and there is no mapping layer between them -- a map between two
vocabularies that differ by one entry is how they drift. `schema.sql`'s CHECK
gained `status_unreadable` and `SCHEMA_VERSION` went 2 -> 3 for exactly this;
`hx.store.records.record_exchange` takes `outcome=` straight off the frame.
(This paragraph said the opposite until Task 7 wrote the first consumer: the
column did not carry the value yet, and the note read as an instruction to
build the mapping the spec forbids.)

## Error classes

`class` is one of:

    scope_denied         refused by scope
    method_denied        refused by the method allow-list
    dangerous_denied     refused by a dangerous-path rule
    rate_limited         slow down and retry; carries retry_after_us
    budget_exhausted     the run's request budget is spent
    not_configured       no configure has been acknowledged, or the send path
                         failed internally
    unmanaged_credential the request carries a credential header the extension
                         did not inject; refused AND never persisted
    transport_error      it was issued and no response came back
    timeout              the deadline passed; the caller has stopped waiting
    bridge_lost          the control channel went away
    bad_frame            the frame could not be read as a request at all
    engagement_mismatch  the frame names another engagement
    bad_config           the configure body could not be acted on
    protocol_mismatch    the frame's `v` is not this protocol version

They split on WHAT HAPPENS NEXT, and a second implementation has to get that
split right or an operator loses a control channel they could have kept:

  * `bad_frame` and `engagement_mismatch` refuse ONE frame and keep the
    channel. Neither is the peer trying to configure us, and neither says
    anything about the frames after it.
  * `bad_config` and `protocol_mismatch` drop to DENY-ALL first. An unusable
    configure means the operator's intent is unknown, and carrying on under the
    PREVIOUS scope would send exactly where an operator narrowing it just said
    not to. `bad_config` keeps the channel, so a corrected configure can
    follow; `protocol_mismatch` ends it, because there is no version left to
    speak.
  * `not_configured` from the send path's internal-failure catch also drops to
    DENY-ALL and closes: a send path that threw is one we no longer understand.

`limit.rate_rps` and `limit.max_requests` must each be a positive integer set
exactly once -- not repeated, not unparseable, and **not zero**; all three are
refused in the `configure` arm, not at first use. Accepting an unreadable limit and refusing the first `send`
is equally fail-closed and much worse to recover from: the extension dials once
and has no reconnect, so the send-time refusal closes the channel and the
corrected configure cannot be sent at all.

`halt` and `resume` carry no `id` and no `deadline_us`. Only `_request()`
stamps those two, and both of these go out through `_send()`: nothing replies
to a control frame, so there is nothing to correlate and no work to abandon at
a deadline. This document claimed both fields for them from Plan 2 until Task
7; the code never sent them.

`halted` is UNSOLICITED and carries no `id`. An auto-halt is decided by the
extension -- a host in distress -- so there is no outstanding request to answer
with it, and without this frame the stop is invisible until the next `send`
fails. `reason` and `host` are what tripped and where; `window` is what it was
measured over, because "5xx rate 40%" is not an explanation without it.
`run.status = 'aborted'` is written from these three, and they exist nowhere
else. A halt an operator asked for needs no such frame: that one already had a
`halt` frame to answer.

## Config body format

The `configure` body is NOT JSON. It is a line-oriented format, because the
extension parses it and a flat parser cannot express nested config:

    key<TAB>value\n

Repeated keys accumulate into a list, in order. Keys and values are UTF-8.
A value may not contain a tab or a newline; the sender rejects such input
rather than escaping it.

Recognised keys:

    scope.include      URL pattern, repeatable
    scope.exclude      URL pattern, repeatable
    dangerous.path     path pattern, repeatable
    method.allow       HTTP method, repeatable
    limit.rate_rps     positive integer, once   -- enforced
    limit.concurrency  integer, once            -- not yet read by anything
    limit.max_requests positive integer, once   -- enforced
    render.allow       host pattern, repeatable

An unrecognised key is an error, not a warning: silently ignoring a key the
sender believed it set is how a scope rule goes missing.

"Positive integer, once" is enforced for the two limit keys the extension
reads, and a body that breaks it is answered `bad_config`. Falling back to the
built-in default instead is the one answer that is wrong in both directions: an
operator who asked for 1 rps would silently get 5, and one who asked for 500
would silently get 5 as well. `limit.concurrency` is not enforced because
nothing reads it yet; it joins the rule in the change that honours it.
