"""RagShield — untrusted documents in, a RAG pipeline that doesn't get played.

Prompt injection is the top real-world attack on retrieval-augmented
chatbots: an attacker hides "ignore your instructions" inside a document
your pipeline fetches, and the model obeys the document instead of you.
RagShield is a from-scratch defense layer — detection, sanitization and
output filtering — implemented in this package with zero dependencies.

    detector      — 6 weighted heuristic families → score + verdict
    sanitizer     — redact, fold, defuse, wrap untrusted text (idempotent)
    output_filter — leak markers & secret-shaped strings out of replies
    pipeline      — RagShield.scan_document / scan_output / sanitize_document
    cli           — python -m ragshield scan | sanitize
    demo          — python -m ragshield.demo, six documents, no arguments
"""
from .pipeline import DocumentScan, OutputScan, RagShield

__all__ = ["DocumentScan", "OutputScan", "RagShield"]
__version__ = "1.0.0"
