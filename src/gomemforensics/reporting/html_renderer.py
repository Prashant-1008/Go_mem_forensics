"""Phase 6G — self-contained, deterministic HTML report rendering.

No external network resources, no CDN, no remote JavaScript, no external
fonts - every byte of the produced HTML is generated locally from the
already-built :class:`~gomemforensics.reporting.models.ReportModel`
(stage 25/39). All content is HTML-escaped before insertion (this module
never trusts evidence-derived text - recovered Go strings, artifact
values, error messages - as safe HTML).

**Secret safety** (stage 30): every table that can contain sensitive
material (credentials, crypto artifacts, persistence artifacts, IOCs)
renders ``redacted_value`` - never ``raw_value``, and never reconstructs
a raw value from a normalized/redacted one. String artifacts (Phase 3
predates the redaction convention and has no ``redacted_value`` field)
are shown in full, length-truncated for display only - not because they
are assumed safe, but because any secret-*shaped* string is already
separately recognized and redacted at the credential/crypto/persistence
layers (see ``docs/architecture/go-reporting.md``).
"""

from __future__ import annotations

from html import escape
from pathlib import Path

from gomemforensics.reporting.models import MAX_STRING_DISPLAY_LENGTH_HTML, MAX_TABLE_ROWS_HTML, ReportModel

_CSS = """
:root { color-scheme: light; }
* { box-sizing: border-box; }
body {
  font-family: -apple-system, "Segoe UI", Arial, sans-serif;
  margin: 0; padding: 0 0 4rem 0; background: #f5f6f8; color: #1c1f26;
  line-height: 1.5;
}
header.cover {
  background: #1c2330; color: #fff; padding: 2.5rem 2rem;
}
header.cover h1 { margin: 0 0 0.5rem 0; font-size: 1.6rem; }
header.cover p { margin: 0.2rem 0; color: #c9d1e0; font-size: 0.9rem; }
nav.toc {
  background: #fff; border-bottom: 1px solid #d7dbe3; padding: 0.75rem 2rem;
  position: sticky; top: 0; z-index: 10;
}
nav.toc a {
  display: inline-block; margin: 0.15rem 0.6rem 0.15rem 0; font-size: 0.82rem;
  color: #2b4c8c; text-decoration: none;
}
nav.toc a:hover { text-decoration: underline; }
main { max-width: 1200px; margin: 0 auto; padding: 0 2rem; }
section { background: #fff; border: 1px solid #d7dbe3; border-radius: 6px;
  margin-top: 1.5rem; padding: 1.25rem 1.5rem; }
section h2 { margin-top: 0; font-size: 1.15rem; border-bottom: 2px solid #eef0f4; padding-bottom: 0.4rem; }
table { border-collapse: collapse; width: 100%; font-size: 0.82rem; margin-top: 0.5rem; }
th, td { border: 1px solid #e3e6ec; padding: 0.35rem 0.5rem; text-align: left; vertical-align: top; }
th { background: #f0f2f6; font-weight: 600; }
tr:nth-child(even) { background: #fafbfc; }
code, .mono { font-family: "Consolas", "SFMono-Regular", monospace; font-size: 0.82rem; }
.badge { display: inline-block; padding: 0.1rem 0.5rem; border-radius: 3px; font-size: 0.75rem; font-weight: 600; }
.badge-high { background: #fbdede; color: #8a1f1f; }
.badge-medium { background: #fdecc8; color: #7a5300; }
.badge-low { background: #e4ecf7; color: #2b4c8c; }
.badge-informational { background: #e6f4ea; color: #1e6b34; }
.badge-error { background: #fbdede; color: #8a1f1f; }
.badge-warning { background: #fdecc8; color: #7a5300; }
.notice { background: #fff8e6; border: 1px solid #e8d28a; border-radius: 4px; padding: 0.6rem 0.9rem; margin: 0.6rem 0; font-size: 0.85rem; }
.notice.critical { background: #fdeaea; border-color: #e6a6a6; }
.disclaimer { background: #eef2f8; border-left: 4px solid #2b4c8c; padding: 0.6rem 0.9rem; margin: 0.6rem 0; font-size: 0.85rem; }
.truncation-notice { font-style: italic; color: #6b7280; font-size: 0.8rem; margin-top: 0.4rem; }
ul.methodology li, ul.limitations li { margin-bottom: 0.4rem; font-size: 0.88rem; }
.empty { color: #8a8f9c; font-style: italic; font-size: 0.85rem; }
footer { max-width: 1200px; margin: 2rem auto 0 auto; padding: 0 2rem; color: #8a8f9c; font-size: 0.78rem; }
"""

_SECTIONS: tuple[tuple[str, str], ...] = (
    ("cover", "Cover / Case Information"),
    ("executive-summary", "Executive Summary"),
    ("evidence", "Evidence"),
    ("validation", "Validation Status"),
    ("environment", "Environment"),
    ("processes", "Processes"),
    ("go-runtimes", "Go Runtime Analysis"),
    ("strings", "Strings"),
    ("functions", "Functions"),
    ("goroutines", "Goroutines"),
    ("network", "Network Artifacts"),
    ("credentials", "Credential Artifacts"),
    ("crypto", "Crypto Artifacts"),
    ("persistence", "Persistence Artifacts"),
    ("iocs", "IOCs"),
    ("correlations", "Correlations"),
    ("findings", "Findings"),
    ("errors", "Errors / Warnings"),
    ("methodology", "Methodology"),
    ("limitations", "Limitations"),
    ("traceability", "Evidence Traceability"),
)


def _e(value) -> str:
    """Escape any evidence-derived value for safe HTML insertion - never
    trust recovered strings/artifact values as pre-sanitized HTML."""
    if value is None:
        return ""
    return escape(str(value))


def _severity_badge(value: str | None) -> str:
    v = (value or "").lower()
    return f'<span class="badge badge-{_e(v) or "low"}">{_e(value or "UNKNOWN")}</span>'


def _table(headers: list[str], rows: list[list], *, empty_message: str = "No entries recovered.") -> str:
    if not rows:
        return f'<p class="empty">{_e(empty_message)}</p>'
    truncated = len(rows) > MAX_TABLE_ROWS_HTML
    shown_rows = rows[:MAX_TABLE_ROWS_HTML]
    head = "".join(f"<th>{_e(h)}</th>" for h in headers)
    body_rows = []
    for row in shown_rows:
        cells = "".join(f"<td>{cell}</td>" for cell in row)  # cells are pre-escaped by callers
        body_rows.append(f"<tr>{cells}</tr>")
    html = f"<table><thead><tr>{head}</tr></thead><tbody>{''.join(body_rows)}</tbody></table>"
    if truncated:
        html += (
            f'<p class="truncation-notice">Showing {MAX_TABLE_ROWS_HTML} of {len(rows)} entries in this HTML '
            "report (a display bound, not evidence loss) - the complete, untruncated set is in the JSON report.</p>"
        )
    return html


def _truncate_display(value: str | None, limit: int = MAX_STRING_DISPLAY_LENGTH_HTML) -> str:
    if value is None:
        return ""
    text = str(value)
    if len(text) <= limit:
        return _e(text)
    return _e(text[:limit]) + f'<span class="truncation-notice"> [+{len(text) - limit} more chars, see JSON]</span>'


def _kv_table(pairs: list[tuple[str, str]]) -> str:
    rows = "".join(f"<tr><th>{_e(k)}</th><td>{v}</td></tr>" for k, v in pairs)
    return f"<table>{rows}</table>"


def _render_cover(report: ReportModel) -> str:
    pairs = [
        ("Case ID", _e(report.case.get("case_id")) or '<span class="empty">not set</span>'),
        ("Tool version", _e(report.report_metadata.get("tool_version"))),
        ("Report schema version", _e(report.report_metadata.get("report_schema_version"))),
        ("Report generated at", _e(report.report_metadata.get("report_generated_at"))),
        ("Evidence file", _e(report.evidence.get("file_name"))),
        ("Evidence SHA-256", f'<span class="mono">{_e(report.evidence.get("sha256"))}</span>'),
    ]
    return f"""
<header class="cover" id="cover">
  <h1>GoMemForensics Forensic Report</h1>
  <p>{_kv_table(pairs)}</p>
  <p class="disclaimer" style="color:#1c1f26;">
    This report presents observed forensic evidence and evidence-based interpretation only.
    It contains no malware verdict, malware/threat/risk score, or automatic attribution.
  </p>
</header>
"""


def _render_executive_summary(report: ReportModel) -> str:
    s = report.executive_summary
    pairs = [
        ("Analysis status", _e(s.get("analysis_status"))),
        ("Evidence", f"{_e(s.get('evidence_file_name'))} (<span class=\"mono\">{_e(s.get('evidence_sha256'))}</span>)"),
        ("Platform / Architecture", f"{_e(s.get('platform'))} / {_e(s.get('architecture'))}"),
        ("Processes discovered", _e(s.get("process_count"))),
        ("Go candidate processes", _e(s.get("go_candidate_process_count"))),
        ("Go runtimes recovered", _e(s.get("go_runtime_recovered_count"))),
        ("Strings / Functions / Goroutines", f"{_e(s.get('strings_recovered'))} / {_e(s.get('functions_recovered'))} / {_e(s.get('goroutines_recovered'))}"),
        ("Network / Credential / Crypto / Persistence artifacts", f"{_e(s.get('network_artifacts'))} / {_e(s.get('credential_artifacts'))} / {_e(s.get('crypto_artifacts'))} / {_e(s.get('persistence_artifacts'))}"),
        ("IOCs (unique)", f"{_e(s.get('ioc_count'))} ({_e(s.get('unique_ioc_count'))} unique)"),
        ("Correlations", _e(s.get("correlation_count"))),
        ("Findings", _e(s.get("finding_count"))),
        ("Findings by severity", ", ".join(f"{_e(k)}: {_e(v)}" for k, v in sorted(s.get("findings_by_severity", {}).items())) or '<span class="empty">none</span>'),
        ("Errors / Warnings", f"{_e(s.get('errors_count'))} / {_e(s.get('warnings_count'))}"),
        ("REAL_MEMORY_VALIDATED", f'<strong>{_e(s.get("real_memory_validated"))}</strong>'),
    ]
    return f"""
<section id="executive-summary">
  <h2>Executive Summary</h2>
  {_kv_table(pairs)}
  <p class="disclaimer">{_e(s.get("note"))}</p>
</section>
"""


def _render_evidence(report: ReportModel) -> str:
    ev = report.evidence
    pairs = [
        ("Input path", _e(ev.get("input_path"))),
        ("File name", _e(ev.get("file_name"))),
        ("File size (bytes)", _e(ev.get("file_size"))),
        ("Hash algorithm", _e(ev.get("hash_algorithm"))),
        ("SHA-256", f'<span class="mono">{_e(ev.get("sha256"))}</span>'),
        ("Analysis timestamp", _e(ev.get("analysis_timestamp"))),
        ("Read-only", _e(ev.get("read_only"))),
    ]
    return f'<section id="evidence"><h2>Evidence</h2>{_kv_table(pairs)}</section>'


def _render_validation(report: ReportModel) -> str:
    v = report.validation
    notice_class = "notice critical" if not v.get("real_memory_validated") else "notice"
    return f"""
<section id="validation">
  <h2>Validation Status</h2>
  <p><strong>REAL_MEMORY_VALIDATED = {_e(v.get("real_memory_validated"))}</strong></p>
  <div class="{notice_class}">{_e(v.get("note"))}</div>
</section>
"""


def _render_environment(report: ReportModel) -> str:
    pairs = [(k, _e(val)) for k, val in report.environment.items()]
    return f'<section id="environment"><h2>Environment</h2>{_kv_table(pairs)}</section>'


def _render_processes(report: ReportModel) -> str:
    headers = ["PID", "Name", "OS", "Arch", "Go candidate", "Go version", "Runtime recovered",
               "Strings", "Funcs", "Goroutines", "Net", "Cred", "Crypto", "Persist", "IOCs", "Corr", "Findings", "Errors"]
    rows = []
    for p in report.process_summaries:
        rows.append([
            _e(p.get("pid")), _e(p.get("process_name")), _e(p.get("os")), _e(p.get("architecture")),
            _e(p.get("is_go_candidate")), _e(p.get("go_version")), _e(p.get("runtime_recovered")),
            _e(p.get("strings_count")), _e(p.get("functions_count")), _e(p.get("goroutines_count")),
            _e(p.get("network_artifacts_count")), _e(p.get("credential_artifacts_count")),
            _e(p.get("crypto_artifacts_count")), _e(p.get("persistence_artifacts_count")),
            _e(p.get("ioc_count")), _e(p.get("correlation_count")), _e(p.get("finding_count")),
            _e(p.get("error_count")),
        ])
    return f'<section id="processes"><h2>Processes</h2>{_table(headers, rows, empty_message="No processes enumerated.")}</section>'


def _render_go_runtimes(report: ReportModel) -> str:
    headers = ["PID", "Process", "Go version", "Architecture", "pclntab", "pcHeader", "moduledata", "Confidence"]
    rows = []
    for r in report.go_runtimes:
        rows.append([
            _e(r.get("pid")), _e(r.get("process_name")), _e(r.get("go_version")), _e(r.get("architecture")),
            _e(r.get("pclntab_address")), _e(r.get("pc_header_address")), _e(r.get("moduledata_address")),
            _e(r.get("confidence")),
        ])
    return f'<section id="go-runtimes"><h2>Go Runtime Analysis</h2>{_table(headers, rows, empty_message="No Go runtime recovered for any process.")}</section>'


def _render_strings(report: ReportModel) -> str:
    headers = ["ID", "PID", "Region", "Classification", "Confidence", "Length", "Address", "Value"]
    rows = []
    for s in report.strings:
        rows.append([
            _e(s.get("id")), _e(s.get("pid")), _e(s.get("region")), _e(s.get("classification")),
            _e(s.get("confidence")), _e(s.get("length")), _e(s.get("string_address")),
            f'<span class="mono">{_truncate_display(s.get("value"))}</span>',
        ])
    return f'<section id="strings"><h2>Strings</h2>{_table(headers, rows, empty_message="No strings recovered.")}</section>'


def _render_functions(report: ReportModel) -> str:
    headers = ["ID", "PID", "Name", "Package", "Classification", "Confidence", "Source file"]
    rows = []
    for f in report.functions:
        rows.append([
            _e(f.get("id")), _e(f.get("pid")), _e(f.get("name")), _e(f.get("package")),
            _e(f.get("classification")), _e(f.get("confidence")), _e(f.get("source_file")),
        ])
    return f'<section id="functions"><h2>Functions</h2>{_table(headers, rows, empty_message="No functions recovered.")}</section>'


def _render_goroutines(report: ReportModel) -> str:
    headers = ["ID", "PID", "Goid", "Status", "Current function", "Frames", "Unwind status", "Confidence"]
    rows = []
    for g in report.goroutines:
        rows.append([
            _e(g.get("id")), _e(g.get("pid")), _e(g.get("goid")), _e(g.get("status_name")),
            _e(g.get("current_function_name")), _e(len(g.get("frames", []))), _e(g.get("unwind_status")),
            _e(g.get("confidence")),
        ])
    return f'<section id="goroutines"><h2>Goroutines</h2>{_table(headers, rows, empty_message="No goroutines recovered.")}</section>'


def _render_network(report: ReportModel) -> str:
    headers = ["ID", "PID", "Type", "Raw value", "Function", "Goroutine", "Confidence", "Validation"]
    rows = []
    for a in report.network_artifacts:
        rows.append([
            _e(a.get("id")), _e(a.get("pid")), _e(a.get("artifact_type")),
            f'<span class="mono">{_truncate_display(a.get("raw_value"))}</span>',
            _e(a.get("function_id")), _e(a.get("goroutine_id")), _e(a.get("confidence")), _e(a.get("validation_status")),
        ])
    return (
        '<section id="network"><h2>Network Artifacts</h2>'
        '<p class="disclaimer">Network artifacts are observed/recovered/classified values only - never a '
        "claim of contact, connection, or C2 activity.</p>"
        f'{_table(headers, rows, empty_message="No network artifacts recovered.")}</section>'
    )


def _render_credentials(report: ReportModel) -> str:
    headers = ["ID", "PID", "Type", "Redacted value", "Function", "Related network", "Confidence", "Validation"]
    rows = []
    for a in report.credential_artifacts:
        rows.append([
            _e(a.get("id")), _e(a.get("pid")), _e(a.get("artifact_type")),
            f'<span class="mono">{_e(a.get("redacted_value"))}</span>',
            _e(a.get("function_id")), _e(a.get("network_artifact_id")), _e(a.get("confidence")), _e(a.get("validation_status")),
        ])
    return (
        '<section id="credentials"><h2>Credential Artifacts</h2>'
        '<p class="disclaimer">Credential/secret material observed in memory. Redacted values are shown - '
        "never raw secret material. This is never a claim that a credential was used, transmitted, or stolen.</p>"
        f'{_table(headers, rows, empty_message="No credential artifacts recovered.")}</section>'
    )


def _render_crypto(report: ReportModel) -> str:
    headers = ["ID", "PID", "Type", "Algorithm", "Redacted value", "Confidence", "Validation"]
    rows = []
    for a in report.crypto_artifacts:
        rows.append([
            _e(a.get("id")), _e(a.get("pid")), _e(a.get("artifact_type")), _e(a.get("algorithm")),
            f'<span class="mono">{_e(a.get("redacted_value"))}</span>', _e(a.get("confidence")), _e(a.get("validation_status")),
        ])
    return (
        '<section id="crypto"><h2>Crypto Artifacts</h2>'
        '<p class="disclaimer">Cryptographic material observed in memory - never a claim that encryption, '
        "decryption, signing, or a key exchange/TLS session actually occurred.</p>"
        f'{_table(headers, rows, empty_message="No crypto artifacts recovered.")}</section>'
    )


def _render_persistence(report: ReportModel) -> str:
    headers = ["ID", "PID", "Platform", "Type", "Mechanism", "Redacted value", "Confidence"]
    rows = []
    for a in report.persistence_artifacts:
        rows.append([
            _e(a.get("id")), _e(a.get("pid")), _e(a.get("platform")), _e(a.get("artifact_type")),
            _e(a.get("persistence_mechanism")), f'<span class="mono">{_e(a.get("redacted_value"))}</span>', _e(a.get("confidence")),
        ])
    return (
        '<section id="persistence"><h2>Persistence Artifacts</h2>'
        '<div class="notice">Persistence-related REFERENCES observed in process memory - this project has no '
        "structured OS-level registry/service/Task-Scheduler/systemd validation. This is never a claim that "
        "persistence was actually established on the operating system.</div>"
        f'{_table(headers, rows, empty_message="No persistence artifacts recovered.")}</section>'
    )


def _render_iocs(report: ReportModel) -> str:
    headers = ["ID", "PID", "IOC type", "Category", "Redacted/normalized value", "Source artifact", "Confidence", "Validation", "Dedup key"]
    rows = []
    for ioc in report.iocs:
        display_value = ioc.get("redacted_value") or (ioc.get("normalized_value") and str(ioc.get("normalized_value"))) or ""
        rows.append([
            _e(ioc.get("id")), _e(ioc.get("pid")), _e(ioc.get("ioc_type")), _e(ioc.get("ioc_category")),
            f'<span class="mono">{_truncate_display(display_value)}</span>',
            _e(ioc.get("source_artifact_id")), _e(ioc.get("confidence")), _e(ioc.get("validation_status")),
            _e(ioc.get("dedup_key")),
        ])
    unique_count = len({ioc.get("dedup_key") for ioc in report.iocs if ioc.get("dedup_key")})
    return (
        f'<section id="iocs"><h2>IOCs</h2><p>{len(report.iocs)} IOC record(s), {unique_count} unique '
        "(by normalized indicator) - every record is preserved individually with its own evidence location; "
        "none are merged.</p>"
        f'{_table(headers, rows, empty_message="No IOCs extracted.")}</section>'
    )


def _render_correlations(report: ReportModel) -> str:
    headers = ["ID", "PID", "Relationship type", "Source", "Target", "Evidence basis"]
    rows = []
    for c in report.correlations:
        rows.append([
            _e(c.get("id")), _e(c.get("pid")), _e(c.get("relationship_type")),
            f'{_e(c.get("source_type"))}:{_e(c.get("source_id"))}',
            f'{_e(c.get("target_type"))}:{_e(c.get("target_id"))}',
            _e(c.get("evidence_basis")),
        ])
    return (
        '<section id="correlations"><h2>Correlations</h2>'
        '<p class="disclaimer">Each relationship restates an already-recorded evidence field as an explicit '
        "edge (e.g. \"artifacts share the same source string evidence\") - never a behavioral claim such as "
        '"the process used the credential to contact the endpoint".</p>'
        f'{_table(headers, rows, empty_message="No correlations recorded.")}</section>'
    )


def _render_findings(report: ReportModel) -> str:
    blocks = []
    for f in report.findings:
        blocks.append(f"""
<div class="notice" style="background:#fff;">
  <p><strong>{_e(f.get("finding_id"))}</strong> — {_e(f.get("title"))} {_severity_badge(f.get("severity"))}</p>
  <p><em>Observed evidence:</em> {_e(f.get("observed_evidence"))}</p>
  <p><em>Interpretation:</em> {_e(f.get("interpretation"))}</p>
  <p>Confidence: {_e(f.get("confidence"))} &nbsp; Validation: {_e(f.get("validation_status"))} &nbsp;
     Supporting IOCs: {_e(", ".join(f.get("supporting_ioc_ids", [])))} &nbsp;
     Functions: {_e(", ".join(f.get("function_ids", [])))} &nbsp;
     Goroutines: {_e(", ".join(f.get("goroutine_ids", [])))}</p>
</div>
""")
    body = "".join(blocks) if blocks else '<p class="empty">No findings generated.</p>'
    return (
        '<section id="findings"><h2>Findings</h2>'
        '<p class="disclaimer">Severity describes forensic/reporting importance only - it is never a malware '
        "probability, threat score, or maliciousness score. There is no overall per-process or per-case "
        "severity/risk score.</p>"
        f"{body}</section>"
    )


def _render_errors(report: ReportModel) -> str:
    def _rows(items):
        out = []
        for e in items:
            out.append([
                _e(e.get("component")), _e(e.get("pid")), _e(e.get("reason")), _e(e.get("message")), _e(e.get("timestamp")),
            ])
        return out

    headers = ["Component", "PID", "Reason", "Message", "Timestamp"]
    return f"""
<section id="errors">
  <h2>Errors / Warnings</h2>
  <h3>Errors <span class="badge badge-error">{len(report.errors)}</span></h3>
  {_table(headers, _rows(report.errors), empty_message="No non-recoverable errors.")}
  <h3>Warnings <span class="badge badge-warning">{len(report.warnings)}</span></h3>
  {_table(headers, _rows(report.warnings), empty_message="No warnings recorded.")}
</section>
"""


def _render_methodology(report: ReportModel) -> str:
    items = "".join(f"<li>{_e(m)}</li>" for m in report.methodology)
    return f'<section id="methodology"><h2>Methodology</h2><ul class="methodology">{items}</ul></section>'


def _render_limitations(report: ReportModel) -> str:
    items = "".join(f"<li>{_e(m)}</li>" for m in report.limitations)
    return f'<section id="limitations"><h2>Limitations</h2><ul class="limitations">{items}</ul></section>'


def _render_traceability(report: ReportModel) -> str:
    blocks = []
    for entry in report.evidence_traceability:
        chain_text = " &rarr; ".join(f'{_e(link.get("type"))}:{_e(link.get("id"))}' for link in entry.get("chain", []))
        blocks.append(f'<p><span class="mono">{chain_text}</span></p>')
    body = "".join(blocks) if blocks else '<p class="empty">No findings to trace.</p>'
    return f'<section id="traceability"><h2>Evidence Traceability</h2>{body}</section>'


def render_html(report: ReportModel) -> str:
    """Render the full, self-contained HTML report. Deterministic given
    the same :class:`ReportModel` input (no random IDs, no unordered-set
    iteration, no current-timestamp-dependent ordering - only
    ``report_metadata.report_generated_at`` reflects render time, and it
    never affects section ordering or content)."""
    nav = "".join(f'<a href="#{sid}">{_e(label)}</a>' for sid, label in _SECTIONS)
    sections = "".join(
        [
            _render_cover(report),
            _render_executive_summary(report),
            _render_evidence(report),
            _render_validation(report),
            _render_environment(report),
            _render_processes(report),
            _render_go_runtimes(report),
            _render_strings(report),
            _render_functions(report),
            _render_goroutines(report),
            _render_network(report),
            _render_credentials(report),
            _render_crypto(report),
            _render_persistence(report),
            _render_iocs(report),
            _render_correlations(report),
            _render_findings(report),
            _render_errors(report),
            _render_methodology(report),
            _render_limitations(report),
            _render_traceability(report),
        ]
    )
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>GoMemForensics Forensic Report</title>
<style>{_CSS}</style>
</head>
<body>
<nav class="toc">{nav}</nav>
<main>
{sections}
</main>
<footer>Generated by GoMemForensics {_e(report.report_metadata.get("tool_version"))} - report schema
{_e(report.report_metadata.get("report_schema_version"))}. This document is a local, offline forensic
report; it contains no external network resources.</footer>
</body>
</html>
"""


def write_html_report(report: ReportModel, output_path: Path) -> None:
    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(render_html(report), encoding="utf-8")
