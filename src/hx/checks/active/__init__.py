"""Checks that build and send their own requests.

`active_safe` in S10 means the request is safe to repeat against a
production target -- idempotent, no state change -- but it is still a request
this tool originates, unlike `passive`'s pure analysis of traffic a browser
already made. Every check here is handed a `hx.checks.probe.ProbeSender`
already bound to its surface and does not own a socket itself; S4's DENY-ALL
gate sits underneath every send.
"""
