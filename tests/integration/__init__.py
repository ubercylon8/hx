"""Tests that launch a real headless Burp Suite.

Marked `integration` and excluded by pyproject's addopts, so `pytest` stays a
few seconds and only `pytest -m integration` pays the JVM.
"""
