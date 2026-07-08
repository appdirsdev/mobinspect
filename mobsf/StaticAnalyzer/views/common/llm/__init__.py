"""Local Granite LLM enrichment (dashboard-only, background, fail-closed).

Everything in this package is additive and best-effort. It runs only AFTER a
scan has completed and persisted, in a separate background task, and never on
the scan code path. Any failure degrades to no AI output; it can never block,
slow, or fail a scan or the report.
"""
