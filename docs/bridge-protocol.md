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
  burp -> py   halted      {v,t,reason,host,window}   unsolicited; no id.
  burp -> py   exchange    {v,t,...}   unsolicited; no id. Defined in a later plan.
  py -> burp   halt        {v,t,id,deadline_us,reason}
  py -> burp   resume      {v,t,id,deadline_us}

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
    limit.rate_rps     integer, once
    limit.concurrency  integer, once
    limit.max_requests integer, once
    render.allow       host pattern, repeatable

An unrecognised key is an error, not a warning: silently ignoring a key the
sender believed it set is how a scope rule goes missing.
