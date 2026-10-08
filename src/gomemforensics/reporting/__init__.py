"""Phase 6G — forensic reporting.

Presentation layer only: consumes an already-produced analysis JSON
(:meth:`gomemforensics.pipeline.AnalysisResult.to_json_dict`'s exact
schema) and renders it as JSON/HTML. Performs no new forensic discovery
- see :mod:`gomemforensics.reporting.models` for the full boundary.
"""
