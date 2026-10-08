"""Phase 6D — Go malware persistence artifact analyzer.

Identifies observable persistence-related artifacts already present in
Go string evidence recovered by Phase 3. Like Phase 6A/6B/6C, this is
artifact *extraction*, never malware classification (CLAUDE.md section
20). Specific to this phase's CORE OBJECTIVE: a recovered string such as
``HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run`` is evidence
that the *string* exists in the binary's memory - it is never treated as
proof that the registry key exists, was written, or that persistence
succeeded. Every interpretation uses one of five precise, non-
overclaiming phrases (never ``PERSISTENCE_CONFIRMED``/
``PERSISTENCE_ESTABLISHED``/``COMMAND_EXECUTED``) - see
:class:`~gomemforensics.analyzers.models.PersistenceArtifact`'s
docstring.

Source grounding (Phase 6D stage 6/7 - full table in
``docs/architecture/go-persistence-artifacts.md``): this module
implements **no structured OS artifact recovery** (registry hives,
service-control-manager records, scheduled-task database entries). The
installed Volatility 3 (2.28.2) genuinely does provide real plugins for
these (``volatility3.framework.plugins.windows.registry.hivelist``/
``printkey``/``scheduled_tasks``, ``volatility3.framework.plugins.windows.svcscan``)
- inspected directly for this phase, not guessed - but every one of them
is a *whole-kernel-symbol* plugin (requires the full Windows kernel
translation layer and version-specific symbol tables), architecturally
unrelated to a specific Go process's own memory, and - critically -
completely unexercisable at even the COMPILED_BINARY_VALIDATED tier this
project relies on everywhere else (a compiled Go executable file has no
registry hive, no SCM database, and no Task Scheduler database embedded
in it at all). Wiring these in now would add real-memory-image-dependent
code with no way to verify correctness in this environment - documented
as NOT_IMPLEMENTED / future work, not silently skipped.

Every detector below is instead purely textual/contextual, operating on
already-decoded Go string *values* Phase 3 already recovered - no Go
version or architecture dependency of its own (same as Phase 6A/6B/6C's
string-based layers).
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from itertools import count

from gomemforensics.analyzers.models import (
    CredentialArtifact,
    CryptoArtifact,
    NetworkArtifact,
    PersistenceArtifact,
    PersistenceArtifactType,
    PersistenceValidationStatus,
)
from gomemforensics.common.models import AnalysisError, ArtifactProvenance, Confidence
from gomemforensics.go_runtime.models import FunctionArtifact, GoroutineArtifact, StringArtifact

ANALYZER_VERSION = "analyzers.persistence/1"

#: Safety bounds (mirrors analyzers/network.py, analyzers/credentials.py,
#: analyzers/crypto.py exactly - not OS/runtime invariants).
MAX_PERSISTENCE_VALUE_LENGTH = 4096
MAX_ARTIFACTS_PER_PROCESS = 5000
#: Stage 29 names these separately; this analyzer never extracts a
#: command/config *substring* independent of the whole recovered string
#: value, so both bounds are simply aliases of the general length bound,
#: documented explicitly rather than silently identical.
MAX_COMMAND_LENGTH = MAX_PERSISTENCE_VALUE_LENGTH
MAX_CONFIG_BLOCK_LENGTH = MAX_PERSISTENCE_VALUE_LENGTH

_PAT = PersistenceArtifactType

#: The five precise interpretation phrases this phase mandates - never
#: any stronger claim (PERSISTENCE_CONFIRMED/PERSISTENCE_ESTABLISHED/
#: COMMAND_EXECUTED do not exist anywhere in this module).
_ARTIFACT_OBSERVED = "PERSISTENCE_ARTIFACT_OBSERVED"
_CONFIGURATION_REFERENCED = "PERSISTENCE_CONFIGURATION_REFERENCED"
_PATH_OBSERVED = "PERSISTENCE_PATH_OBSERVED"
_COMMAND_OBSERVED = "PERSISTENCE_COMMAND_OBSERVED"
_FUNCTION_ASSOCIATED = "PERSISTENCE_FUNCTION_ASSOCIATED"


@dataclass(frozen=True)
class _Classification:
    artifact_type: PersistenceArtifactType
    platform: str
    persistence_mechanism: str
    normalized: dict
    confidence: Confidence
    interpretation: str
    notes: str | None = None


def _note(interpretation: str, detail: str) -> str:
    if detail:
        return f"{interpretation}: {detail} This is evidence of a recovered string, not proof of an actual, successfully established persistence mechanism."
    return f"{interpretation}. This is evidence of a recovered string, not proof of an actual, successfully established persistence mechanism."


# ---------------------------------------------------------------------------
# Windows detectors
# ---------------------------------------------------------------------------

_WIN_REGISTRY_RUN_RE = re.compile(
    r"(?i)\bHK(?:CU|LM|EY_CURRENT_USER|EY_LOCAL_MACHINE)\\Software\\Microsoft\\Windows\\CurrentVersion\\(Run(?:Once)?)\b"
)
_WIN_WINLOGON_KEY_RE = re.compile(r"(?i)\bWinlogon\\(Shell|Userinit)\b")
_WIN_WINLOGON_PATH_RE = re.compile(
    r"(?i)\bHK(?:CU|LM)\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\b"
)
_WIN_STARTUP_FOLDER_RE = re.compile(
    r"(?i)AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\b"
)
_WIN_SCHTASKS_CMD_RE = re.compile(r"(?i)\bschtasks(?:\.exe)?\s+/create\b")
_WIN_SCHTASKS_PS_RE = re.compile(r"(?i)\b(New-ScheduledTask(?:Action)?|Register-ScheduledTask)\b")
_WIN_SERVICE_API_RE = re.compile(r"\b(CreateService[AW]?|OpenSCManager[AW]?|StartService[AW]?)\b")
_WIN_SERVICE_CMD_RE = re.compile(r"(?i)\bsc(?:\.exe)?\s+create\b")
_WIN_SERVICE_IMAGEPATH_RE = re.compile(r"(?i)\bImagePath\s*[:=]\s*\S+")
_WIN_WMI_CLASS_NAMES = (
    "__EventFilter",
    "__FilterToConsumerBinding",
    "CommandLineEventConsumer",
    "ActiveScriptEventConsumer",
)
_WIN_WMI_NAMESPACE_RE = re.compile(r"root\\subscription", re.IGNORECASE)
_WIN_APPINIT_RE = re.compile(r"\b(AppInit_DLLs|AppCertDLLs)\b")
_WIN_IFEO_RE = re.compile(r"(?i)\bImage File Execution Options\b")


def _classify_windows(value: str) -> _Classification | None:
    match = _WIN_REGISTRY_RUN_RE.search(value)
    if match:
        variant = match.group(1)
        mechanism = "registry_runonce_key" if variant.lower() == "runonce" else "registry_run_key"
        return _Classification(
            _PAT.WINDOWS_REGISTRY_RUN, "windows", mechanism, {"key_variant": variant},
            Confidence.HIGH, _PATH_OBSERVED,
            _note(_PATH_OBSERVED, "A Windows Run/RunOnce autostart registry path was recognized."),
        )

    if _WIN_WINLOGON_KEY_RE.search(value) or _WIN_WINLOGON_PATH_RE.search(value):
        return _Classification(
            _PAT.WINDOWS_WINLOGON, "windows", "winlogon_shell_userinit", {},
            Confidence.MEDIUM, _PATH_OBSERVED,
            _note(_PATH_OBSERVED, "A Winlogon Shell/Userinit-related registry path was recognized."),
        )

    if _WIN_STARTUP_FOLDER_RE.search(value):
        return _Classification(
            _PAT.WINDOWS_STARTUP_FOLDER, "windows", "startup_folder_path", {},
            Confidence.HIGH, _PATH_OBSERVED,
            _note(_PATH_OBSERVED, "A Windows user Startup folder path was recognized."),
        )

    if _WIN_SCHTASKS_CMD_RE.search(value) or _WIN_SCHTASKS_PS_RE.search(value):
        return _Classification(
            _PAT.WINDOWS_SCHEDULED_TASK_REFERENCE, "windows", "scheduled_task_command", {},
            Confidence.MEDIUM, _COMMAND_OBSERVED,
            _note(_COMMAND_OBSERVED, "A scheduled-task creation command/API name was recognized."),
        )

    if _WIN_SERVICE_CMD_RE.search(value):
        return _Classification(
            _PAT.WINDOWS_SERVICE_REFERENCE, "windows", "service_create_command", {},
            Confidence.MEDIUM, _COMMAND_OBSERVED,
            _note(_COMMAND_OBSERVED, "A Windows service-creation command ('sc create') was recognized."),
        )
    if _WIN_SERVICE_API_RE.search(value):
        return _Classification(
            _PAT.WINDOWS_SERVICE_REFERENCE, "windows", "service_api_reference", {},
            Confidence.LOW, _ARTIFACT_OBSERVED,
            _note(_ARTIFACT_OBSERVED, "A Windows service-control-manager API name was recognized - a bare API name reference, not a configured service."),
        )
    if _WIN_SERVICE_IMAGEPATH_RE.search(value):
        return _Classification(
            _PAT.WINDOWS_SERVICE_REFERENCE, "windows", "service_image_path", {},
            Confidence.MEDIUM, _PATH_OBSERVED,
            _note(_PATH_OBSERVED, "A service 'ImagePath' value assignment was recognized."),
        )

    wmi_hits = [name for name in _WIN_WMI_CLASS_NAMES if name in value]
    has_wmi_namespace = bool(_WIN_WMI_NAMESPACE_RE.search(value))
    if wmi_hits or has_wmi_namespace:
        if len(wmi_hits) >= 2:
            return _Classification(
                _PAT.WINDOWS_WMI_PERSISTENCE, "windows", "wmi_filter_consumer_binding",
                {"classes": wmi_hits}, Confidence.MEDIUM, _CONFIGURATION_REFERENCED,
                _note(_CONFIGURATION_REFERENCED, f"Multiple related WMI persistence class names were recognized together: {', '.join(wmi_hits)}."),
            )
        mechanism = "wmi_class_reference" if wmi_hits else "wmi_subscription_namespace"
        detail_name = wmi_hits[0] if wmi_hits else "root\\subscription"
        return _Classification(
            _PAT.WINDOWS_WMI_PERSISTENCE, "windows", mechanism, {"class": detail_name},
            Confidence.LOW, _ARTIFACT_OBSERVED,
            _note(_ARTIFACT_OBSERVED, f"A single WMI persistence-related name ({detail_name}) was recognized - not a confirmed subscription."),
        )

    if _WIN_APPINIT_RE.search(value):
        return _Classification(
            _PAT.WINDOWS_APPINIT, "windows", "appinit_dlls", {},
            Confidence.MEDIUM, _PATH_OBSERVED,
            _note(_PATH_OBSERVED, "An AppInit_DLLs/AppCertDLLs registry value name was recognized."),
        )

    if _WIN_IFEO_RE.search(value):
        return _Classification(
            _PAT.WINDOWS_IFEO, "windows", "ifeo_debugger", {},
            Confidence.MEDIUM, _PATH_OBSERVED,
            _note(_PATH_OBSERVED, "An Image File Execution Options reference was recognized."),
        )

    return None


# ---------------------------------------------------------------------------
# Linux detectors
# ---------------------------------------------------------------------------

_LINUX_SYSTEMD_UNIT_PATH_RE = re.compile(r"(?:/etc|/usr/lib|/lib)/systemd/system/[\w@.-]+\.service\b")
_LINUX_SYSTEMD_USER_UNIT_RE = re.compile(r"\.config/systemd/user/[\w@.-]+\.service\b")
_LINUX_SYSTEMD_CONTENT_RE = re.compile(r"\[Service\]|\[Install\]")
_LINUX_SYSTEMD_EXECSTART_RE = re.compile(r"(?m)^\s*ExecStart\s*=")
_LINUX_SYSTEMCTL_ENABLE_RE = re.compile(r"\bsystemctl\s+(?:--user\s+)?enable\b")

_LINUX_CRON_PATH_RE = re.compile(r"/etc/cron\.(?:d|daily|hourly|weekly|monthly)/\S*|/etc/crontab\b")
_LINUX_CRON_SPOOL_RE = re.compile(r"/var/spool/cron/crontabs?/\S*")
_LINUX_CRONTAB_CMD_RE = re.compile(r"\bcrontab\s+-[elru]\b")

_LINUX_SHELL_PROFILE_RE = re.compile(r"(?:^|[~/])\.(?:bashrc|bash_profile|zshrc)\b|/etc/(?:profile|bash\.bashrc)\b")

_LINUX_AUTOSTART_PATH_RE = re.compile(r"\.config/autostart/[\w.-]+\.desktop\b")
_LINUX_DESKTOP_ENTRY_RE = re.compile(r"\[Desktop Entry\]")
_LINUX_DESKTOP_EXEC_RE = re.compile(r"(?m)^\s*Exec\s*=")

_LINUX_INIT_D_RE = re.compile(r"/etc/init\.d/[\w.-]+")
_LINUX_RC_LOCAL_RE = re.compile(r"/etc/rc\.local\b")

_LINUX_AUTHORIZED_KEYS_PATH_RE = re.compile(r"\.ssh/authorized_keys\b")
_LINUX_AUTHORIZED_KEY_ENTRY_RE = re.compile(
    r"^(ssh-(?:rsa|ed25519|dss)|ecdsa-sha2-nistp(?:256|384|521))\s+[A-Za-z0-9+/]+=*(?:\s+\S+)?$"
)

_LINUX_LD_PRELOAD_ENV_RE = re.compile(r"\bLD_PRELOAD\s*=")
_LINUX_LD_SO_PRELOAD_RE = re.compile(r"/etc/ld\.so\.preload\b")


def _classify_linux(value: str) -> _Classification | None:
    if _LINUX_SYSTEMD_CONTENT_RE.search(value) and _LINUX_SYSTEMD_EXECSTART_RE.search(value):
        return _Classification(
            _PAT.LINUX_SYSTEMD_UNIT, "linux", "systemd_unit_content", {},
            Confidence.HIGH, _CONFIGURATION_REFERENCED,
            _note(_CONFIGURATION_REFERENCED, "Recognizable systemd unit file content ([Service]/[Install] plus ExecStart=) was found."),
        )
    if _LINUX_SYSTEMD_USER_UNIT_RE.search(value):
        return _Classification(
            _PAT.LINUX_SYSTEMD_UNIT, "linux", "systemd_user_unit_path", {},
            Confidence.HIGH, _PATH_OBSERVED,
            _note(_PATH_OBSERVED, "A per-user systemd unit file path was recognized."),
        )
    if _LINUX_SYSTEMD_UNIT_PATH_RE.search(value):
        return _Classification(
            _PAT.LINUX_SYSTEMD_UNIT, "linux", "systemd_unit_path", {},
            Confidence.HIGH, _PATH_OBSERVED,
            _note(_PATH_OBSERVED, "A system-wide systemd unit file path was recognized."),
        )
    if _LINUX_SYSTEMCTL_ENABLE_RE.search(value):
        return _Classification(
            _PAT.LINUX_SYSTEMD_UNIT, "linux", "systemctl_enable_command", {},
            Confidence.MEDIUM, _COMMAND_OBSERVED,
            _note(_COMMAND_OBSERVED, "A 'systemctl enable' command was recognized."),
        )

    if _LINUX_CRON_PATH_RE.search(value) or _LINUX_CRON_SPOOL_RE.search(value):
        return _Classification(
            _PAT.LINUX_CRON, "linux", "cron_path", {},
            Confidence.HIGH, _PATH_OBSERVED,
            _note(_PATH_OBSERVED, "A cron configuration path was recognized."),
        )
    if _LINUX_CRONTAB_CMD_RE.search(value):
        return _Classification(
            _PAT.LINUX_CRON, "linux", "cron_command", {},
            Confidence.MEDIUM, _COMMAND_OBSERVED,
            _note(_COMMAND_OBSERVED, "A 'crontab' editing command was recognized."),
        )

    if _LINUX_SHELL_PROFILE_RE.search(value):
        return _Classification(
            _PAT.LINUX_SHELL_PROFILE, "linux", "shell_profile_path", {},
            Confidence.MEDIUM, _PATH_OBSERVED,
            _note(_PATH_OBSERVED, "A shell profile path was recognized."),
        )

    if _LINUX_DESKTOP_ENTRY_RE.search(value) and _LINUX_DESKTOP_EXEC_RE.search(value):
        return _Classification(
            _PAT.LINUX_AUTOSTART, "linux", "desktop_autostart_entry", {},
            Confidence.HIGH, _CONFIGURATION_REFERENCED,
            _note(_CONFIGURATION_REFERENCED, "Recognizable XDG .desktop autostart entry content ([Desktop Entry] plus Exec=) was found."),
        )
    if _LINUX_AUTOSTART_PATH_RE.search(value):
        return _Classification(
            _PAT.LINUX_AUTOSTART, "linux", "xdg_autostart_path", {},
            Confidence.MEDIUM, _PATH_OBSERVED,
            _note(_PATH_OBSERVED, "An XDG autostart directory path was recognized."),
        )

    if _LINUX_RC_LOCAL_RE.search(value):
        return _Classification(
            _PAT.LINUX_INIT_SCRIPT, "linux", "rc_local", {},
            Confidence.MEDIUM, _PATH_OBSERVED,
            _note(_PATH_OBSERVED, "An /etc/rc.local path was recognized."),
        )
    if _LINUX_INIT_D_RE.search(value):
        return _Classification(
            _PAT.LINUX_INIT_SCRIPT, "linux", "init_d_script", {},
            Confidence.MEDIUM, _PATH_OBSERVED,
            _note(_PATH_OBSERVED, "A SysV /etc/init.d/ script path was recognized."),
        )

    if _LINUX_AUTHORIZED_KEY_ENTRY_RE.match(value):
        return _Classification(
            _PAT.LINUX_AUTHORIZED_KEY_ENTRY, "linux", "authorized_key_entry", {},
            Confidence.HIGH, _ARTIFACT_OBSERVED,
            _note(_ARTIFACT_OBSERVED, "A complete SSH public-key line (authorized_keys entry shape) was recognized. Presence in memory does not establish it was written to a filesystem authorized_keys file."),
        )
    if _LINUX_AUTHORIZED_KEYS_PATH_RE.search(value):
        return _Classification(
            _PAT.LINUX_AUTHORIZED_KEYS_PATH, "linux", "authorized_keys_path", {},
            Confidence.MEDIUM, _PATH_OBSERVED,
            _note(_PATH_OBSERVED, "A '.ssh/authorized_keys' path was recognized."),
        )

    if _LINUX_LD_SO_PRELOAD_RE.search(value):
        return _Classification(
            _PAT.LINUX_LOADER_PRELOAD, "linux", "ld_so_preload_file", {},
            Confidence.HIGH, _PATH_OBSERVED,
            _note(_PATH_OBSERVED, "An /etc/ld.so.preload path was recognized."),
        )
    if _LINUX_LD_PRELOAD_ENV_RE.search(value):
        return _Classification(
            _PAT.LINUX_LOADER_PRELOAD, "linux", "ld_preload_env", {},
            Confidence.MEDIUM, _PATH_OBSERVED,
            _note(_PATH_OBSERVED, "An LD_PRELOAD environment-style assignment was recognized."),
        )

    return None


def classify_persistence_string(value: str) -> _Classification | None:
    """Classify one already-recovered Go string's value for Windows and
    Linux persistence-related shapes.

    Windows and Linux detectors run independently and are mutually
    exclusive in practice (the patterns do not overlap in shape - a
    registry path and a systemd unit path share no syntax) - Windows
    detectors are checked first purely for determinism, not because of
    any actual ambiguity between the two platforms (stage 3: "Do not mix
    Windows and Linux semantics" - upheld by construction, not by
    ordering).
    """
    if not value or len(value) > MAX_PERSISTENCE_VALUE_LENGTH:
        return None
    return _classify_windows(value) or _classify_linux(value)


# ---------------------------------------------------------------------------
# Redaction (mirrors analyzers/credentials.py and analyzers/crypto.py)
# ---------------------------------------------------------------------------


def redact_value(value: str) -> str:
    """Deterministic, generic redaction - separate copy per analyzer
    module, matching the established Phase 6B/6C pattern."""
    if len(value) <= 8:
        return "*" * len(value)
    return f"{value[:3]}...{value[-3:]}"


# ---------------------------------------------------------------------------
# Association (stages 19/20/21/22) - explicit evidence chains only.
# ---------------------------------------------------------------------------


def _build_function_string_references(functions: list[FunctionArtifact]) -> dict[str, set[str]]:
    """Identical evidence chain to Phase 6A/6B/6C's own copies."""
    refs: dict[str, set[str]] = {}
    for func in functions:
        for call_site in func.recovered_call_sites:
            for argument in call_site.recovered_arguments:
                if argument.type_hint == "string" and argument.value and argument.value.startswith("string_ref:"):
                    string_id = argument.value[len("string_ref:") :]
                    refs.setdefault(string_id, set()).add(func.id)
    return refs


def _build_goroutine_function_references(goroutines: list[GoroutineArtifact]) -> dict[str, set[str]]:
    refs: dict[str, set[str]] = {}
    for goroutine in goroutines:
        function_ids: set[str] = set()
        if goroutine.current_function_id:
            function_ids.add(goroutine.current_function_id)
        for frame in goroutine.frames:
            if frame.function_id:
                function_ids.add(frame.function_id)
        for function_id in function_ids:
            refs.setdefault(function_id, set()).add(goroutine.id)
    return refs


def _build_shared_source_references(artifacts: list) -> dict[str, str]:
    """``StringArtifact.id -> other-analyzer artifact.id`` for any prior-
    phase artifact sharing the same source string (deterministic lowest-
    sorted id if more than one shares it)."""
    refs: dict[str, list[str]] = {}
    for artifact in artifacts:
        refs.setdefault(artifact.source_artifact_id, []).append(artifact.id)
    return {string_id: min(ids) for string_id, ids in refs.items()}


@dataclass(frozen=True)
class PersistenceAnalysisStats:
    """Per-process persistence-analyzer counters (mirrors
    :class:`~gomemforensics.analyzers.network.NetworkAnalysisStats`)."""

    strings_scanned: int = 0
    artifacts_extracted: int = 0
    strings_skipped_length_bound: int = 0
    capped: bool = False
    artifacts_by_type: dict[str, int] = field(default_factory=dict)


def extract_persistence_artifacts(
    pid: int,
    process_name: str | None,
    go_version: str | None,
    architecture: str,
    strings: list[StringArtifact],
    functions: list[FunctionArtifact],
    goroutines: list[GoroutineArtifact],
    network_artifacts: list[NetworkArtifact],
    credential_artifacts: list[CredentialArtifact],
    crypto_artifacts: list[CryptoArtifact],
) -> tuple[list[PersistenceArtifact], list[AnalysisError], PersistenceAnalysisStats]:
    """Extract :class:`PersistenceArtifact` records from one process's
    already-recovered evidence.

    Never re-scans process memory, never touches the filesystem/registry/
    service-control-manager/task scheduler, never executes anything -
    purely a classification pass over already-recovered
    :class:`StringArtifact` objects (CLAUDE.md section 24 applies exactly
    as Phase 6A/6B/6C: one malformed/unexpected string never aborts the
    rest).
    """
    errors: list[AnalysisError] = []
    artifacts: list[PersistenceArtifact] = []
    artifacts_by_type: dict[str, int] = {}
    strings_skipped_length_bound = 0
    capped = False
    id_counter = count(1)

    function_refs = _build_function_string_references(functions)
    goroutine_refs = _build_goroutine_function_references(goroutines)
    network_refs = _build_shared_source_references(network_artifacts)
    credential_refs = _build_shared_source_references(credential_artifacts)
    crypto_refs = _build_shared_source_references(crypto_artifacts)

    strings_scanned = 0
    for source in strings:
        if source.pid != pid:
            continue
        strings_scanned += 1

        if len(artifacts) >= MAX_ARTIFACTS_PER_PROCESS:
            capped = True
            continue
        if len(source.value) > MAX_PERSISTENCE_VALUE_LENGTH:
            strings_skipped_length_bound += 1
            continue

        try:
            classification = classify_persistence_string(source.value)
        except Exception as exc:  # one malformed/unexpected string must not abort the rest
            errors.append(
                AnalysisError(
                    component="analyzers.persistence",
                    message=f"Persistence classification failed unexpectedly for string {source.id}: {exc}",
                    pid=pid,
                )
            )
            continue
        if classification is None:
            continue

        function_ids = function_refs.get(source.id, set())
        goroutine_ids: set[str] = set()
        for function_id in function_ids:
            goroutine_ids |= goroutine_refs.get(function_id, set())

        notes = classification.notes
        if function_ids:
            notes = f"{notes} {_FUNCTION_ASSOCIATED}: referenced by a recovered function's call-site argument evidence."

        artifact_id = f"PERSIST-{pid}-{next(id_counter):04d}"
        related_artifacts = [source.id] + sorted(function_ids) + sorted(goroutine_ids)
        network_artifact_id = network_refs.get(source.id)
        credential_artifact_id = credential_refs.get(source.id)
        crypto_artifact_id = crypto_refs.get(source.id)
        for extra_id in (network_artifact_id, credential_artifact_id, crypto_artifact_id):
            if extra_id:
                related_artifacts.append(extra_id)

        provenance = ArtifactProvenance(
            artifact_id=artifact_id,
            artifact_type=f"persistence_{classification.artifact_type.value}",
            analyzer="analyzers.persistence.extract_persistence_artifacts",
            extraction_method="go_string_persistence_classification",
            confidence=classification.confidence,
            pid=pid,
            virtual_address=f"0x{source.data_address:x}",
            memory_region=source.region,
            analyzer_version=ANALYZER_VERSION,
            related_artifacts=related_artifacts,
        )
        artifacts.append(
            PersistenceArtifact(
                id=artifact_id,
                pid=pid,
                process_name=process_name,
                platform=classification.platform,
                artifact_type=classification.artifact_type,
                persistence_mechanism=classification.persistence_mechanism,
                raw_value=source.value,
                redacted_value=redact_value(source.value),
                normalized_value=classification.normalized,
                address=source.data_address,
                length=len(source.value),
                memory_region=source.region,
                source_artifact_id=source.id,
                function_id=min(function_ids) if function_ids else None,
                goroutine_id=min(goroutine_ids) if goroutine_ids else None,
                network_artifact_id=network_artifact_id,
                credential_artifact_id=credential_artifact_id,
                crypto_artifact_id=crypto_artifact_id,
                extraction_method="go_string_persistence_classification",
                confidence=classification.confidence,
                validation_status=PersistenceValidationStatus.STRUCTURALLY_VALID,
                go_version=go_version,
                architecture=architecture,
                provenance=provenance,
                notes=notes,
            )
        )
        type_key = classification.artifact_type.value
        artifacts_by_type[type_key] = artifacts_by_type.get(type_key, 0) + 1

    if capped:
        errors.append(
            AnalysisError(
                component="analyzers.persistence",
                message=(
                    f"Persistence artifact cap ({MAX_ARTIFACTS_PER_PROCESS}) reached for pid {pid}; "
                    "remaining recovered strings were not classified (ANALYSIS_BOUNDED, not a failure)"
                ),
                pid=pid,
                recoverable=True,
            )
        )

    stats = PersistenceAnalysisStats(
        strings_scanned=strings_scanned,
        artifacts_extracted=len(artifacts),
        strings_skipped_length_bound=strings_skipped_length_bound,
        capped=capped,
        artifacts_by_type=artifacts_by_type,
    )
    return artifacts, errors, stats
