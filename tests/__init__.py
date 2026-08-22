"""Makes `tests` a package so `from tests.integration import burp_fixture` works.

Without this file that import fails with ModuleNotFoundError: pytest only puts
the *first* directory lacking an __init__.py on sys.path, which for a bare
tests/ directory is tests/ itself, not the repository root.
"""
