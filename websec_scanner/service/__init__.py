"""The agency API (decision D12): a hosted service that lets an agency's backend request scans and read results.

This package is the one place in the project that is meant to be exposed to a network. The CLI, the local web
UI and the scanning core (``run_scan()``) never import it and do not depend on it; it needs the optional
``service`` extra (``pip install websec-scanner[service]``), except ``ids``, ``security``, ``db``, ``config`` and
``admin``, which use only the standard library.
"""
