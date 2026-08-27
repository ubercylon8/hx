"""Checks that read only what a browser already fetched.

`passive` in S10 means analysis only, zero extra requests, always on. These
need no bridge, no scope authorisation and no permission beyond the capture
that already happened -- which is why they run even when Burp is not up.
"""
