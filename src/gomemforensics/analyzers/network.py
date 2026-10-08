"""Phase 6A — Go network artifact analyzer.

Recovers network-related artifacts (IPv4/IPv6 addresses, hostnames, URLs,
``host:port`` endpoints) that are already observable in Go strings
recovered by Phase 3 (:mod:`gomemforensics.go_runtime.strings`). This is
artifact *extraction*, never malware classification (CLAUDE.md section 20)
- no artifact produced here is ever labeled malicious, suspicious, or
scored.

Source grounding (Phase 6A stage 3 - see
``docs/architecture/go-network-artifacts.md`` for the full source
archaeology table): this module deliberately does **not** parse any Go
runtime or standard-library struct. A recovered :class:`StringArtifact`'s
``value`` is plain, already-decoded Go string content - classifying its
*textual* shape (does it look like an IPv4 address? a URL?) has no Go
version or architecture dependency at all, unlike Phase 2-5's struct
parsing. Structured network objects (``net.TCPAddr``, ``netip.Addr``,
``net/url.URL``, ``crypto/tls.ConnectionState``) were investigated and are
explicitly NOT implemented - see the module docstring's "Structured
objects" section below and the architecture doc for why.

Function/goroutine association (stage 7/8) reuses an evidence chain that
already exists from Phase 4/5, never address proximity:
``FunctionArtifact.recovered_call_sites[].recovered_arguments[]`` records
``type_hint="string"`` with ``value="string_ref:<StringArtifact.id>"``
whenever backward analysis resolved a call-site argument to a known
recovered string's backing address
(:func:`gomemforensics.go_runtime.backward_analysis._classify_rip_target`).
That is the only link this module trusts to say "function X references
string Y" - never "string Y's address happens to be near function X's
code". From there, a goroutine's unwound :class:`GoroutineFrame`\\ s (or
its ``current_function_id``) either do or do not include that function -
again a direct field reference, never proximity.

Structured objects (Phase 6A stage 9) - investigated, NOT implemented:

- ``net.TCPAddr``/``net.UDPAddr`` (``IP net.IP; Port int; Zone string``,
  verified in the local go1.26.2 ``net/tcpsock.go``/``net/udpsock.go``):
  field layout is stable and exported, but there is no reliable way to
  *locate* a live instance's address. Unlike ``pclntab``/``moduledata``,
  these have no fixed anchor; finding one would require heap-object
  type-index correlation (Phase 3's ``mspan.py``/``types.py`` machinery),
  and Go's dead-code elimination means the type descriptor for
  ``net.TCPAddr`` is only present in a compiled binary at all if the
  analyzed program actually uses ``net`` via an interface conversion -
  the project's own benign fixture does not, so this would be untestable
  beyond a synthetic buffer even if implemented. Documented as
  NOT IMPLEMENTED, not fabricated.
- ``netip.Addr`` (local go1.26.2 ``net/netip/netip.go``): its `z` field is
  a ``unique.Handle[addrDetail]`` - Go's own interned-value handle type,
  an intentionally opaque, unexported representation with no documented
  stable memory layout. Parsing it would mean guessing an unexported,
  explicitly-unstable internal representation - exactly what CLAUDE.md
  section 40 and Phase 6A's "SOURCE FIRST" principle forbid. NOT
  IMPLEMENTED, permanently out of scope unless Go documents this layout.
- ``net/url.URL`` (local go1.26.2 ``net/url/url.go``): exported string
  fields (stable layout), but the same addressability problem as
  ``net.TCPAddr`` applies, plus many ``url.URL`` values never escape to
  the heap at all (stack-allocated, invisible to any heap scan). NOT
  IMPLEMENTED.
- ``crypto/tls.ConnectionState``: large, version-sensitive struct with
  fields referencing further structures (certificates, cipher state).
  Out of scope for this phase's effort budget and not source-archaeology-
  complete; NOT IMPLEMENTED, not attempted.

OS-level socket correlation (stage 10) is explicitly future work - this
module never assumes ``net.Conn`` implies a live OS socket or an actual
network connection (CLAUDE.md section 20 / stage 8: a function/string
relationship is not proof of a network operation having occurred).
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from itertools import count
from urllib.parse import urlsplit

from gomemforensics.analyzers.models import NetworkArtifact, NetworkArtifactType, NetworkValidationStatus
from gomemforensics.common.models import AnalysisError, ArtifactProvenance, Confidence
from gomemforensics.go_runtime.models import FunctionArtifact, GoroutineArtifact, StringArtifact

ANALYZER_VERSION = "analyzers.network/1"

#: Safety bounds (Phase 6A stage 17 - not Go runtime invariants, purely
#: this analyzer's own cost control). A string longer than this is never
#: regex/urlsplit-processed by this analyzer (it is still preserved,
#: untouched, as its own StringArtifact - only *network* classification
#: of it is skipped). Comfortably above any realistic URL/hostname/IP
#: literal while bounding worst-case per-string work.
MAX_STRING_VALUE_LENGTH = 4096

#: Hard cap on emitted NetworkArtifacts per process. When reached, the
#: remaining strings for that process are left unclassified and the
#: condition is recorded explicitly (an AnalysisError plus a statistics
#: counter) rather than silently truncated (stage 17: "Do not silently
#: truncate evidence").
MAX_ARTIFACTS_PER_PROCESS = 5000

_SUPPORTED_URL_SCHEMES = frozenset({"http", "https"})

#: Curated common-TLD allowlist used to gate bare hostname/domain
#: recognition (Phase 6A stage 6). This is a deliberate, documented
#: false-positive control: a two-(or-more)-label dotted string whose
#: final label is a real TLD is overwhelmingly likely to be an actual
#: hostname, whereas Go source-level dotted identifiers (``io.Reader``,
#: ``time.Now``, ``os.Exit``) essentially never coincide with a real TLD.
#: The direct, documented cost is that a legitimate hostname under an
#: exotic/new TLD not in this list will not be recognized - see
#: docs/architecture/go-network-artifacts.md's false-positive-control
#: section and the Phase 6A final report's Limitations.
_TLD_ALLOWLIST = frozenset(
    {
        "com", "net", "org", "io", "gov", "edu", "mil", "info", "biz", "co",
        "dev", "app", "xyz", "top", "site", "online", "shop", "club", "live",
        "tech", "cloud", "store", "space", "website", "link", "click", "icu",
        "vip", "pro", "name", "mobi", "tv", "me", "cc", "ws", "wtf", "onion",
        "ru", "su", "cn", "de", "uk", "us", "jp", "kr", "in", "fr", "it",
        "es", "nl", "se", "no", "fi", "dk", "pl", "ua", "tr", "ir", "sa",
        "br", "mx", "ca", "au", "nz", "za", "ch", "at", "be", "gr", "pt",
        "cz", "hu", "ro", "bg", "id", "vn", "th", "sg", "hk", "tw", "il",
        "ae", "eu", "int", "arpa", "local", "test", "example", "invalid",
    }
)

_HOSTNAME_LABEL_RE = re.compile(r"^[A-Za-z0-9_]([A-Za-z0-9_-]{0,61}[A-Za-z0-9_])?$")
_IPV4_SYNTAX_RE = re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")
_URL_SCHEME_RE = re.compile(r"^([A-Za-z][A-Za-z0-9+.-]*)://")
_HOST_PORT_RE = re.compile(r"^(?P<host>\[[0-9A-Fa-f:]+\]|[^:\s]+):(?P<port>\d{1,5})$")


@dataclass(frozen=True)
class NetworkAnalysisStats:
    """Per-process network-analyzer counters (mirrors
    :class:`~gomemforensics.go_runtime.models.GoroutineRecoveryStats`)."""

    strings_scanned: int = 0
    artifacts_extracted: int = 0
    strings_skipped_length_bound: int = 0
    capped: bool = False
    artifacts_by_type: dict[str, int] = field(default_factory=dict)


@dataclass(frozen=True)
class _Classification:
    artifact_type: NetworkArtifactType
    normalized: dict
    notes: str | None = None


def _ip_facts(ip_obj) -> dict:
    return {
        "is_private": ip_obj.is_private,
        "is_loopback": ip_obj.is_loopback,
        "is_multicast": ip_obj.is_multicast,
        "is_link_local": ip_obj.is_link_local,
        "is_reserved": ip_obj.is_reserved,
        "is_unspecified": ip_obj.is_unspecified,
        "is_global": ip_obj.is_global,
    }


def _classify_ipv4(value: str) -> _Classification | None:
    # Cheap syntactic pre-filter before the stdlib parse - keeps this a
    # fast reject for the overwhelming majority of non-IP strings, and
    # guarantees exactly 4 dot-separated groups before ipaddress ever
    # sees it (ipaddress itself is also strict, but the pre-filter avoids
    # doing that work on strings with colons/letters/etc. at all).
    if not _IPV4_SYNTAX_RE.match(value):
        return None
    try:
        ip_obj = ipaddress.IPv4Address(value)
    except ValueError:
        return None
    return _Classification(
        NetworkArtifactType.IPV4,
        {"ip": str(ip_obj), **_ip_facts(ip_obj)},
    )


def _classify_ipv6(value: str) -> _Classification | None:
    if ":" not in value:
        return None
    try:
        ip_obj = ipaddress.IPv6Address(value)
    except ValueError:
        return None
    return _Classification(
        NetworkArtifactType.IPV6,
        {"ip": str(ip_obj), **_ip_facts(ip_obj)},
    )


def _is_valid_hostname_label(label: str) -> bool:
    return bool(_HOSTNAME_LABEL_RE.match(label)) if label else False


def _classify_hostname_text(value: str) -> _Classification | None:
    """Structural hostname/domain validation shared by the bare-hostname
    path and the ``host:port``/URL host-component validation.

    Deliberately excludes anything already recognized as a valid IPv4/IPv6
    address (checked by the caller ordering, never re-derived here) and
    anything containing a path separator (Go import paths / filesystem
    paths - stage 6 false-positive control).
    """
    if "/" in value or "\\" in value:
        return None
    if value.lower() == "localhost":
        return _Classification(NetworkArtifactType.HOSTNAME, {"hostname": "localhost", "fqdn": False})

    fqdn = value.endswith(".")
    body = value[:-1] if fqdn else value
    if not body:
        return None
    labels = body.split(".")
    if len(labels) < 2:
        return None
    if not all(_is_valid_hostname_label(label) for label in labels):
        return None
    tld = labels[-1].lower()
    if tld not in _TLD_ALLOWLIST:
        return None
    return _Classification(
        NetworkArtifactType.HOSTNAME,
        {"hostname": body.lower(), "fqdn": fqdn},
    )


def _classify_hostname(value: str) -> _Classification | None:
    # A bare hostname candidate must not itself be a valid IPv4/IPv6
    # literal (those are classified separately, by the caller's ordering)
    if _classify_ipv4(value) is not None or _classify_ipv6(value) is not None:
        return None
    return _classify_hostname_text(value)


def _validate_host_component(host: str) -> bool:
    """True if ``host`` (already stripped of any ``[...]`` brackets) is a
    valid IPv4 literal, IPv6 literal, ``localhost``, or a TLD-allowlisted
    hostname - the only host forms this analyzer's ``host:port``/URL
    parsing accepts (stage 6 false-positive control extended to endpoint
    parsing)."""
    if _classify_ipv4(host) is not None:
        return True
    try:
        ipaddress.IPv6Address(host)
        return True
    except ValueError:
        pass
    if host.lower() == "localhost":
        return True
    return _classify_hostname_text(host) is not None


def _classify_host_port(value: str) -> _Classification | None:
    match = _HOST_PORT_RE.match(value)
    if not match:
        return None
    host_raw = match.group("host")
    port_raw = match.group("port")

    port = int(port_raw)
    if port > 65535:
        return None

    is_bracketed_ipv6 = host_raw.startswith("[") and host_raw.endswith("]")
    host = host_raw[1:-1] if is_bracketed_ipv6 else host_raw
    if not host:
        return None
    if not _validate_host_component(host):
        return None

    return _Classification(
        NetworkArtifactType.HOST_PORT,
        {"host": host.lower() if not is_bracketed_ipv6 else host, "port": port, "bracketed_ipv6": is_bracketed_ipv6},
    )


def _classify_url(value: str) -> _Classification | None:
    scheme_match = _URL_SCHEME_RE.match(value)
    if not scheme_match:
        return None
    scheme = scheme_match.group(1).lower()
    if scheme not in _SUPPORTED_URL_SCHEMES:
        return None

    try:
        parts = urlsplit(value)
        hostname = parts.hostname
        port = parts.port  # raises ValueError for an out-of-range/malformed port
    except ValueError:
        return None

    if not hostname:
        return None
    if not _validate_host_component(hostname):
        return None

    return _Classification(
        NetworkArtifactType.URL,
        {
            "scheme": scheme,
            "hostname": hostname.lower(),
            "port": port,
            "path": parts.path,
            "query": parts.query,
            "fragment": parts.fragment,
        },
    )


def classify_network_string(value: str) -> _Classification | None:
    """Classify one already-recovered Go string's value, or return
    ``None`` if it matches no supported network-artifact shape.

    Ordering matters and is deterministic: URL (has an unambiguous
    ``scheme://`` prefix) is checked before ``host:port`` and IPv4/IPv6,
    since a URL's netloc would otherwise be misparsed by those narrower
    rules; IPv6 is checked before ``host:port`` so an unbracketed literal
    IPv6 address is never mistaken for a malformed endpoint; IPv4 is
    checked before bare hostname so a dotted-quad never falls through to
    hostname's (deliberately laxer, TLD-allowlist-gated) rules.
    """
    if not value or len(value) > MAX_STRING_VALUE_LENGTH:
        return None
    return (
        _classify_url(value)
        or _classify_ipv6(value)
        or _classify_host_port(value)
        or _classify_ipv4(value)
        or _classify_hostname(value)
    )


def _build_function_string_references(functions: list[FunctionArtifact]) -> dict[str, set[str]]:
    """``StringArtifact.id -> {FunctionArtifact.id, ...}`` via the
    existing, explicit ``string_ref:<id>`` evidence chain backward
    analysis already records (Phase 4.1) - never address proximity."""
    refs: dict[str, set[str]] = {}
    for func in functions:
        for call_site in func.recovered_call_sites:
            for argument in call_site.recovered_arguments:
                if argument.type_hint == "string" and argument.value and argument.value.startswith("string_ref:"):
                    string_id = argument.value[len("string_ref:") :]
                    refs.setdefault(string_id, set()).add(func.id)
    return refs


def _build_goroutine_function_references(goroutines: list[GoroutineArtifact]) -> dict[str, set[str]]:
    """``FunctionArtifact.id -> {GoroutineArtifact.id, ...}`` via each
    goroutine's ``current_function_id`` and unwound frames' own
    ``function_id`` fields - direct field references, never proximity."""
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


def extract_network_artifacts(
    pid: int,
    process_name: str | None,
    go_version: str | None,
    architecture: str,
    strings: list[StringArtifact],
    functions: list[FunctionArtifact],
    goroutines: list[GoroutineArtifact],
) -> tuple[list[NetworkArtifact], list[AnalysisError], NetworkAnalysisStats]:
    """Extract :class:`NetworkArtifact` records from one process's already
    -recovered Go strings.

    Never re-scans process memory independently (stage 13: "Do not
    introduce an independent second Go-memory scanning pipeline") - every
    artifact traces back to an existing :class:`StringArtifact` via
    ``source_artifact_id``. A malformed/unexpected individual string never
    aborts the rest (CLAUDE.md section 24): classification failures on one
    string are simply "no artifact produced for this string", and any
    genuinely unexpected exception is caught per-string.
    """
    errors: list[AnalysisError] = []
    artifacts: list[NetworkArtifact] = []
    artifacts_by_type: dict[str, int] = {}
    strings_skipped_length_bound = 0
    capped = False

    function_refs = _build_function_string_references(functions)
    goroutine_refs = _build_goroutine_function_references(goroutines)

    id_counter = count(1)
    strings_scanned = 0
    for source in strings:
        if source.pid != pid:
            continue
        strings_scanned += 1

        if len(artifacts) >= MAX_ARTIFACTS_PER_PROCESS:
            capped = True
            continue

        if len(source.value) > MAX_STRING_VALUE_LENGTH:
            strings_skipped_length_bound += 1
            continue

        try:
            classification = classify_network_string(source.value)
        except Exception as exc:  # one malformed/unexpected string must not abort the rest
            errors.append(
                AnalysisError(
                    component="analyzers.network",
                    message=f"Network classification failed unexpectedly for string {source.id}: {exc}",
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

        artifact_id = f"NET-{pid}-{next(id_counter):04d}"
        related_artifacts = [source.id] + sorted(function_ids) + sorted(goroutine_ids)
        provenance = ArtifactProvenance(
            artifact_id=artifact_id,
            artifact_type=f"network_{classification.artifact_type.value}",
            analyzer="analyzers.network.extract_network_artifacts",
            extraction_method="go_string_network_classification",
            confidence=Confidence.MEDIUM,
            pid=pid,
            virtual_address=f"0x{source.data_address:x}",
            memory_region=source.region,
            analyzer_version=ANALYZER_VERSION,
            related_artifacts=related_artifacts,
        )
        artifact = NetworkArtifact(
            id=artifact_id,
            pid=pid,
            process_name=process_name,
            artifact_type=classification.artifact_type,
            raw_value=source.value,
            normalized_value=classification.normalized,
            address=source.data_address,
            length=len(source.value),
            memory_region=source.region,
            source_artifact_id=source.id,
            function_id=min(function_ids) if function_ids else None,
            goroutine_id=min(goroutine_ids) if goroutine_ids else None,
            extraction_method="go_string_network_classification",
            confidence=Confidence.MEDIUM,
            validation_status=NetworkValidationStatus.STRUCTURALLY_VALID,
            go_version=go_version,
            architecture=architecture,
            provenance=provenance,
            notes=classification.notes,
        )
        artifacts.append(artifact)
        type_key = classification.artifact_type.value
        artifacts_by_type[type_key] = artifacts_by_type.get(type_key, 0) + 1

    if capped:
        errors.append(
            AnalysisError(
                component="analyzers.network",
                message=(
                    f"Network artifact cap ({MAX_ARTIFACTS_PER_PROCESS}) reached for pid {pid}; "
                    "remaining recovered strings were not classified (bounded analysis, not a failure)"
                ),
                pid=pid,
                recoverable=True,
            )
        )

    stats = NetworkAnalysisStats(
        strings_scanned=strings_scanned,
        artifacts_extracted=len(artifacts),
        strings_skipped_length_bound=strings_skipped_length_bound,
        capped=capped,
        artifacts_by_type=artifacts_by_type,
    )
    return artifacts, errors, stats
