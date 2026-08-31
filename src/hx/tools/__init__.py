"""The tool layer: one definition, many adapters.

Spec section 8 opens with the architecture -- "One definition; an MCP adapter
in v1 and an embedded loop later" -- so what is built here is the DEFINITION.
Every transport is a thin projection of `registry.TOOLS`.

Importing this package does NOT import the handlers. `hx.tools.impl` does that,
and an adapter imports it explicitly, so a test can exercise the registry
machinery against specs of its own without eleven real tools appearing in it.
"""
