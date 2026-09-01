"""Transports. Each one is a projection of `hx.tools.registry.TOOLS`.

An adapter validates nothing, authorises nothing and journals nothing: it turns
a request into `dispatch(ctx, name, args, why=...)` and an envelope into
whatever its transport speaks. Anything more here is a second place the rules
live.
"""
