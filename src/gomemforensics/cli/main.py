"""GoMemForensics command-line interface.

Built on Click rather than Typer: Click is the smaller, more direct
dependency (Typer itself wraps Click and pulls in additional transitive
dependencies such as ``rich`` and ``shellingham``), and this CLI's surface
at this phase - four straightforward subcommands and a handful of global
flags - does not need Typer's extra type-hint-driven parameter inference.
Click also gives explicit control over exit codes, which matters for a
forensic tool whose CLI results may be scripted.
"""

from __future__ import annotations

import json
import platform
from pathlib import Path

import click

from gomemforensics import PROJECT_PHASE, __version__
from gomemforensics.acquisition.evidence import EvidenceMetadata, EvidenceValidationError, EvidenceValidator
from gomemforensics.architecture.x86_64 import X86_64Layout
from gomemforensics.common.logging import LogLevel, configure_logging, get_logger
from gomemforensics.os.linux import LINUX
from gomemforensics.os.windows import WINDOWS
from gomemforensics.pipeline import has_fatal_error, run_analysis
from gomemforensics.reporting.html_renderer import write_html_report
from gomemforensics.reporting.json_renderer import write_json_report
from gomemforensics.reporting.models import ReportGenerationError, ReportModel
from gomemforensics.volatility.integration import DependencyStatus, probe_dependencies

#: Exit code conventions used consistently across all subcommands.
EXIT_OK = 0
EXIT_VALIDATION_ERROR = 1
EXIT_UNEXPECTED_ERROR = 2
EXIT_ANALYSIS_ERROR = 3
EXIT_REPORT_ERROR = 4

#: Used when --output is not supplied. Never inside the evidence directory.
DEFAULT_ANALYZE_OUTPUT = Path("reports") / "analysis.json"
DEFAULT_REPORT_OUTPUT_DIR = Path("reports")

logger = get_logger("cli")


def _resolve_log_level(quiet: bool, verbose: bool, debug: bool) -> LogLevel:
    """Resolve the mutually-overlapping verbosity flags to a single level.

    Precedence: ``--debug`` > ``--verbose`` > ``--quiet`` > default normal.
    """
    if debug:
        return LogLevel.DEBUG
    if verbose:
        return LogLevel.VERBOSE
    if quiet:
        return LogLevel.QUIET
    return LogLevel.NORMAL


@click.group()
@click.option("--quiet", is_flag=True, help="Suppress all but error-level diagnostic output.")
@click.option("--verbose", is_flag=True, help="Enable verbose internal diagnostic output.")
@click.option("--debug", is_flag=True, help="Enable full debug diagnostic output (includes addresses).")
@click.version_option(version=__version__, prog_name="gomemforensics")
@click.pass_context
def cli(ctx: click.Context, quiet: bool, verbose: bool, debug: bool) -> None:
    """GoMemForensics: automated Go malware memory forensics and runtime artifact analysis.

    Offline, passive analysis of Windows/Linux memory images for Go
    runtime artifacts. Never modifies evidence; never contacts recovered
    network indicators.
    """
    level = _resolve_log_level(quiet, verbose, debug)
    configure_logging(level)
    ctx.ensure_object(dict)
    ctx.obj["log_level"] = level


@cli.command("version")
def version_command() -> None:
    """Display the GoMemForensics version."""
    click.echo(f"GoMemForensics {__version__} ({PROJECT_PHASE})")


def _echo_dependency(status: DependencyStatus) -> None:
    if status.installed:
        click.echo(f"  {status.name}: installed (version {status.version or 'unknown'})")
    else:
        click.echo(f"  {status.name}: NOT installed")


@cli.command("info")
def info_command() -> None:
    """Display environment, dependency, and current capability information."""
    deps = probe_dependencies()
    x86_64 = X86_64Layout()

    click.echo(f"GoMemForensics {__version__} ({PROJECT_PHASE})")
    click.echo("")
    click.echo("Environment:")
    click.echo(f"  Python version:      {platform.python_version()}")
    click.echo(f"  Platform:            {platform.system()} {platform.release()} ({platform.machine()})")
    click.echo("")
    click.echo("Dependencies:")
    _echo_dependency(deps.volatility3)
    _echo_dependency(deps.capstone)
    click.echo("")
    click.echo("Current analysis targets:")
    click.echo(f"  {WINDOWS.name}: {', '.join(WINDOWS.supported_architectures)}")
    click.echo(f"  {LINUX.name}: {', '.join(LINUX.supported_architectures)}")
    click.echo("  ARM64: planned future support (Phase 10), not currently implemented.")
    click.echo("")
    click.echo(
        f"Primary architecture layout implemented: {x86_64.architecture_name} "
        f"(pointer_size={x86_64.pointer_size}, endianness={x86_64.endianness})"
    )
    click.echo("")
    click.echo(
        "Note: `analyze` now performs real evidence validation, Volatility "
        "initialization, OS/architecture detection, process enumeration, "
        "Go process/runtime detection (pclntab/pcHeader/moduledata), Go "
        "string recovery (heap via allspans/mspan, and static section "
        "scanning), Go function recovery (ftab/_func metadata, source/"
        "package classification, ArgInfo shape, and - x86-64 with a "
        "confidently-resolved ABI era only - Capstone backward call-site "
        "argument analysis), Go goroutine recovery (allgs discovery, "
        "structural g validation, and - x86-64 only - pcsp-based stack "
        "unwinding; see docs/architecture/go-goroutines.md for what "
        "remains genuinely unvalidated against a real memory image), and "
        "Go network artifact extraction (IPv4/IPv6/hostname/URL/host:port "
        "recognition within already-recovered Go strings, with explicit "
        "function/goroutine association where an evidence chain exists - "
        "extraction only, never a maliciousness verdict; see "
        "docs/architecture/go-network-artifacts.md), and Go credential/"
        "secret artifact extraction (context-gated recognition of "
        "password/token/API-key/PEM-private-key/database-credential/"
        "cookie/JWT-shaped values within already-recovered Go strings, "
        "with deterministic redaction and explicit function/goroutine/"
        "network association - never a claim that a value is a valid, "
        "live, or actually-used credential; see "
        "docs/architecture/go-credential-artifacts.md), and Go "
        "cryptographic artifact extraction (PEM public-key/certificate "
        "boundary recognition, a curated crypto-context/cipher-suite "
        "identifier set, and evidence-backed AES key-material recognition "
        "via Phase 4 call-site argument evidence - never a claim that "
        "encryption/decryption occurred or that a key was used, only "
        "KEY_MATERIAL_PASSED_AS_ARGUMENT where call-site evidence "
        "actually supports it; private-key material is reused from Phase "
        "6B, never re-parsed; see "
        "docs/architecture/go-crypto-artifacts.md), and Go persistence "
        "artifact extraction (platform-aware, Windows/Linux-specific "
        "recognition of registry Run/Winlogon/startup-folder/AppInit/"
        "IFEO/service/scheduled-task/WMI references and systemd/cron/"
        "shell-profile/autostart/authorized_keys/LD_PRELOAD references "
        "within already-recovered Go strings - observed strings only, "
        "never proof a registry key exists, a service was created, or "
        "persistence was actually established; see "
        "docs/architecture/go-persistence-artifacts.md), and Phase 6E IOC "
        "extraction/cross-artifact correlation (normalizes qualifying "
        "network/credential/crypto/persistence artifacts into IOC "
        "records and restates their already-existing evidence-chain "
        "fields as explicit, typed relationship records - no new "
        "detection, no memory-proximity correlation, no malware "
        "verdict, no network/DNS/reputation lookup; see "
        "docs/architecture/go-ioc-correlation.md), and Phase 6F findings/"
        "evidence-assessment generation (a closed, evidence-backed "
        "finding taxonomy summarizing already-recovered IOCs/"
        "correlations, always separating observed_evidence from "
        "interpretation - a Finding is an evidence assessment, never a "
        "malware verdict, malware score, threat score, reputation "
        "result, or automatic attribution; see "
        "docs/architecture/go-findings.md), and Phase 6G forensic "
        "reporting (a presentation-only layer - `gomemforensics report "
        "<analysis.json> --format json|html` - that renders an "
        "already-produced analysis JSON as a deterministic, self-"
        "contained JSON or HTML report: executive summary, per-process "
        "summary, Go runtime/string/function/goroutine/artifact/IOC/"
        "correlation/finding sections, an evidence-traceability chain "
        "view, and explicit REAL_MEMORY_VALIDATED/limitations "
        "disclosure - it performs no new memory access or detection, "
        "and never produces a malware verdict or score; PDF generation "
        "is deferred, no dependency for it is installed; see "
        "docs/architecture/go-reporting.md)."
    )


def _echo_evidence_metadata(metadata: EvidenceMetadata) -> None:
    click.echo("[+] Evidence validated")
    click.echo(f"    Path:        {metadata.input_path}")
    click.echo(f"    File name:   {metadata.file_name}")
    click.echo(f"    Size:        {metadata.file_size:,} bytes")
    click.echo(f"    {metadata.hash_algorithm}:      {metadata.sha256}")
    click.echo(f"    Timestamp:   {metadata.analysis_timestamp}")
    click.echo(f"    Read-only:   {metadata.read_only}")
    if metadata.case_id:
        click.echo(f"    Case ID:     {metadata.case_id}")


@cli.command("validate")
@click.argument("image_path", type=click.Path(path_type=Path))
@click.option("--case-id", default=None, help="Optional case identifier to record in evidence metadata.")
@click.pass_context
def validate_command(ctx: click.Context, image_path: Path, case_id: str | None) -> None:
    """Validate an evidence file: confirm it exists, hash it, report its size.

    IMAGE_PATH is never modified.
    """
    validator = EvidenceValidator()
    try:
        metadata = validator.validate(image_path, case_id=case_id)
    except EvidenceValidationError as exc:
        click.echo(f"[!] Evidence validation failed: {exc}", err=True)
        ctx.exit(EXIT_VALIDATION_ERROR)
        return

    _echo_evidence_metadata(metadata)
    ctx.exit(EXIT_OK)


@cli.command("analyze")
@click.argument("image_path", type=click.Path(path_type=Path))
@click.option("--case-id", default=None, help="Optional case identifier to record in evidence metadata.")
@click.option(
    "--output",
    "output_path",
    default=None,
    type=click.Path(path_type=Path),
    help=f"Path to write the JSON analysis result. Defaults to {DEFAULT_ANALYZE_OUTPUT}.",
)
@click.option(
    "--format",
    "output_format",
    default="json",
    type=click.Choice(["json"], case_sensitive=False),
    help="Output format. Only JSON is implemented at this phase.",
)
@click.pass_context
def analyze_command(
    ctx: click.Context,
    image_path: Path,
    case_id: str | None,
    output_path: Path | None,
    output_format: str,
) -> None:
    """Run the forensic analysis pipeline against IMAGE_PATH.

    Evidence validation -> Volatility initialization -> OS/architecture
    detection -> process enumeration -> Go process/runtime detection
    (pclntab, pcHeader, Go version, moduledata) -> Go string recovery
    (heap via allspans/mspan, and static section scanning) -> Go function
    recovery (ftab/_func metadata, classification, ArgInfo shape, and -
    x86-64 with a confidently-resolved ABI era only - Capstone backward
    call-site argument analysis) -> Go goroutine recovery (allgs
    discovery, structural g validation, and - x86-64 only - pcsp-based
    stack unwinding) -> Go network artifact extraction (IPv4/IPv6/
    hostname/URL/host:port recognition within recovered strings) -> Go
    credential/secret artifact extraction (context-gated password/token/
    API-key/PEM-key/database-credential/cookie/JWT-shaped recognition,
    deterministically redacted) -> Go cryptographic artifact extraction
    (PEM public-key/certificate recognition, crypto-context identifiers,
    evidence-backed AES key-material recognition) -> Go persistence
    artifact extraction (platform-aware Windows/Linux persistence-
    reference recognition - observed strings only, never proof
    persistence was established) -> IOC extraction and cross-artifact
    correlation (deterministic normalization/deduplication and typed
    relationship records, never a malware verdict) -> finding generation
    (a closed, evidence-backed taxonomy summarizing IOCs/correlations -
    an evidence assessment, never a malware verdict/score) -> JSON
    output. Run `gomemforensics report` against the resulting JSON file
    to render an examiner-readable HTML (or JSON) report - see
    docs/architecture/go-reporting.md. IMAGE_PATH is never modified, and
    the report is never written inside the evidence file's own directory
    unless explicitly requested via --output.
    """
    resolved_output = output_path or DEFAULT_ANALYZE_OUTPUT

    click.echo(f"[+] Validating evidence: {image_path}")
    try:
        result = run_analysis(image_path, case_id=case_id)
    except EvidenceValidationError as exc:
        click.echo(f"[!] Evidence validation failed: {exc}", err=True)
        ctx.exit(EXIT_VALIDATION_ERROR)
        return

    click.echo(
        f"[+] Evidence validated ({result.evidence.file_size:,} bytes, "
        f"{result.evidence.hash_algorithm} {result.evidence.sha256})"
    )

    fatal = has_fatal_error(result)
    if fatal:
        for error in result.errors:
            if not error.recoverable:
                click.echo(f"[!] {error.message}", err=True)
        click.echo("[!] Volatility could not process this image. Writing a partial report.", err=True)
    else:
        click.echo(f"[+] Operating system: {result.os}")
        click.echo(f"[+] Architecture: {result.architecture}")
        click.echo(f"[+] Processes discovered: {result.statistics.processes_discovered}")
        click.echo(f"[+] Processes with memory access: {result.statistics.processes_with_memory_access}")
        click.echo(f"[+] Candidate Go processes: {result.statistics.go_candidate_processes}")
        click.echo(f"[+] Go runtimes reconstructed: {result.statistics.go_runtimes_reconstructed}")
        click.echo(
            f"[+] Strings recovered: {result.statistics.strings_recovered} "
            f"(heap: {result.statistics.strings_recovered_heap}, "
            f"static: {result.statistics.strings_recovered_static})"
        )
        functions_recovered = result.statistics.extra.get("functions_recovered", 0)
        click.echo(f"[+] Functions recovered: {functions_recovered}")
        if functions_recovered:
            call_sites = result.statistics.extra.get("call_sites_analyzed", 0)
            arguments = result.statistics.extra.get("arguments_recovered", 0)
            click.echo(f"[+] Call sites analyzed: {call_sites} (arguments recovered: {arguments})")
        goroutines_discovered = result.statistics.extra.get("goroutines_discovered", 0)
        click.echo(f"[+] Goroutines recovered: {goroutines_discovered}")
        if goroutines_discovered:
            scanned = result.statistics.extra.get("goroutine_candidates_scanned", 0)
            invalid = result.statistics.extra.get("goroutine_invalid_candidates", 0)
            click.echo(f"[+] Goroutine candidates scanned: {scanned} (invalid: {invalid})")
            frames = result.statistics.extra.get("goroutine_frames_recovered", 0)
            complete = result.statistics.extra.get("goroutine_unwind_complete", 0)
            failures = result.statistics.extra.get("goroutine_unwind_failures", 0)
            click.echo(
                f"[+] Stack frames recovered: {frames} "
                f"(unwind complete: {complete}, unwind failures: {failures})"
            )
        network_artifacts = result.statistics.extra.get("network_artifacts_extracted", 0)
        click.echo(f"[+] Network artifacts extracted: {network_artifacts}")
        credential_artifacts = result.statistics.extra.get("credential_artifacts_extracted", 0)
        click.echo(f"[+] Credential/secret artifacts extracted: {credential_artifacts}")
        crypto_artifacts = result.statistics.extra.get("crypto_artifacts_extracted", 0)
        click.echo(f"[+] Cryptographic artifacts extracted: {crypto_artifacts}")
        persistence_artifacts = result.statistics.extra.get("persistence_artifacts_extracted", 0)
        click.echo(f"[+] Persistence artifacts extracted: {persistence_artifacts}")
        iocs_extracted = result.statistics.extra.get("iocs_extracted", 0)
        iocs_unique = result.statistics.extra.get("iocs_unique", 0)
        click.echo(f"[+] IOCs extracted: {iocs_extracted} ({iocs_unique} unique)")
        correlations_emitted = result.statistics.extra.get("correlations_emitted", 0)
        click.echo(f"[+] Correlation relationships: {correlations_emitted}")
        findings_generated = result.statistics.extra.get("findings_generated", 0)
        click.echo(f"[+] Findings generated: {findings_generated}")
        if findings_generated:
            finding_type_counts = {
                key[len("findings_") :]: value
                for key, value in result.statistics.extra.items()
                if key.startswith("findings_") and key not in ("findings_generated",)
            }
            summary = ", ".join(f"{name}: {count_value}" for name, count_value in sorted(finding_type_counts.items()))
            if summary:
                click.echo(f"    ({summary})")
        if result.statistics.errors_count:
            click.echo(f"[!] Per-process errors recorded: {result.statistics.errors_count}")

    result.write_json(resolved_output)
    click.echo(f"[+] Report written: {resolved_output}")
    click.echo("")
    click.echo("[!] IOCs, correlations, and findings are evidence-derived,")
    click.echo("    deterministic, offline, and non-reputational - a Finding is an")
    click.echo("    evidence assessment, never a malware verdict, threat score, or")
    click.echo("    proof that an artifact was actually used/contacted/executed/")
    click.echo("    downloaded/installed. Run 'gomemforensics report' against this")
    click.echo("    JSON file for an examiner-readable HTML report. PDF generation")
    click.echo("    is deferred - see docs/architecture/go-reporting.md.")

    ctx.exit(EXIT_ANALYSIS_ERROR if fatal else EXIT_OK)


@cli.command("report")
@click.argument("analysis_json_path", type=click.Path(path_type=Path, exists=True, dir_okay=False))
@click.option(
    "--output",
    "output_path",
    default=None,
    type=click.Path(path_type=Path),
    help="Path to write the rendered report. Defaults to reports/report.<format>.",
)
@click.option(
    "--format",
    "output_format",
    default="html",
    type=click.Choice(["json", "html"], case_sensitive=False),
    help="Report format. PDF is deferred - see docs/architecture/go-reporting.md.",
)
@click.pass_context
def report_command(
    ctx: click.Context,
    analysis_json_path: Path,
    output_path: Path | None,
    output_format: str,
) -> None:
    """Render a forensic report from an already-produced analysis JSON file.

    ANALYSIS_JSON_PATH is the output of a prior `gomemforensics analyze`
    run. This command performs no new forensic analysis and never
    re-scans memory - it only reads the supplied JSON and renders it as
    a presentation-layer report: JSON (the original data plus an
    executive summary, per-process summary, methodology, limitations,
    and evidence-traceability chains) or a self-contained static HTML
    document (no external network resources, no CDN, no remote
    JavaScript). Sensitive artifact types (credentials, crypto,
    persistence, IOCs) are rendered using their redacted values, never
    raw secret material. PDF generation is deferred - see
    docs/architecture/go-reporting.md for why.
    """
    click.echo(f"[+] Reading analysis result: {analysis_json_path}")
    try:
        raw_text = analysis_json_path.read_text(encoding="utf-8")
        data = json.loads(raw_text)
    except OSError as exc:
        click.echo(f"[!] Could not read analysis file: {exc}", err=True)
        ctx.exit(EXIT_REPORT_ERROR)
        return
    except json.JSONDecodeError as exc:
        click.echo(f"[!] Analysis file is not valid JSON: {exc}", err=True)
        ctx.exit(EXIT_REPORT_ERROR)
        return

    try:
        report = ReportModel.from_analysis_dict(data)
    except ReportGenerationError as exc:
        click.echo(f"[!] Could not build report: {exc}", err=True)
        ctx.exit(EXIT_REPORT_ERROR)
        return

    format_lower = output_format.lower()
    resolved_output = output_path or (DEFAULT_REPORT_OUTPUT_DIR / f"report.{format_lower}")

    if format_lower == "json":
        write_json_report(report, resolved_output)
    elif format_lower == "html":
        write_html_report(report, resolved_output)
    else:
        # Defense in depth - click.Choice already rejects this at parse
        # time, but a programmatic caller of this function should still
        # fail clearly rather than silently doing nothing (stage 33).
        click.echo(f"[!] Unsupported report format: {output_format}", err=True)
        ctx.exit(EXIT_REPORT_ERROR)
        return

    summary = report.executive_summary
    click.echo(
        f"[+] Findings: {summary['finding_count']}  "
        f"IOCs: {summary['ioc_count']} ({summary['unique_ioc_count']} unique)  "
        f"Correlations: {summary['correlation_count']}"
    )
    click.echo(f"[+] REAL_MEMORY_VALIDATED = {report.validation['real_memory_validated']}")
    click.echo(f"[+] Report written: {resolved_output}")
    ctx.exit(EXIT_OK)


if __name__ == "__main__":
    cli()
