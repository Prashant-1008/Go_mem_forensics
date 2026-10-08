"""Per-process Go runtime detection orchestration.

Pipeline (approved Phase 2 plan): process -> pclntab candidates -> best
validated pcHeader -> Go version estimate -> moduledata candidates anchored
on that pcHeader -> a validated :class:`~gomemforensics.go_runtime.models.GoRuntime`.

Confidence policy (never silently promoted to "confirmed Go"):

- ``HIGH``: a magic-validated pcHeader AND a structurally-validated
  moduledata were both recovered.
- ``MEDIUM``: a magic-validated pcHeader was recovered, but no moduledata
  candidate validated (or none was found).
- ``LOW``: only a structural (non-magic) pcHeader candidate validated - a
  process at this level is never marked ``is_go_candidate`` (approved plan
  Section 10: "A process with only a random magic-byte match must NOT
  automatically become a confirmed Go process").
- ``UNKNOWN``: nothing validated.
"""

from __future__ import annotations

from dataclasses import dataclass

from gomemforensics.common.logging import get_logger
from gomemforensics.common.memory import MemoryReader, MemoryRegion
from gomemforensics.common.models import AnalysisError, ArtifactProvenance, Confidence, FailureReason
from gomemforensics.go_runtime.models import GoRuntime, ModuledataCandidate, PclntabCandidate, PclntabDetectionStatus
from gomemforensics.go_runtime.moduledata import ModuledataParser
from gomemforensics.go_runtime.pclntab import PclntabParser
from gomemforensics.go_runtime.version import GoVersionDetector

logger = get_logger("go_runtime.detector")

#: Element size, in bytes, of a typelinks entry (`[]int32`) - fixed by the
#: Go language spec's int32 size, not architecture-dependent.
_TYPELINKS_ELEMENT_SIZE = 4


@dataclass
class GoDetectionResult:
    """Everything Phase 2 recovered (or attempted) for one process."""

    runtime: GoRuntime | None
    pclntab_candidates: list[PclntabCandidate]
    moduledata_candidates: list[ModuledataCandidate]
    errors: list[AnalysisError]


class GoProcessDetector:
    """Runs the full Phase 2 detection pipeline for a single process."""

    def __init__(self) -> None:
        self._version_detector = GoVersionDetector()

    def detect(
        self,
        pid: int,
        architecture: str,
        pointer_size: int,
        reader: MemoryReader,
        regions: list[MemoryRegion],
    ) -> GoDetectionResult:
        errors: list[AnalysisError] = []

        pclntab_parser = PclntabParser(reader, pointer_size)
        try:
            pclntab_candidates = pclntab_parser.scan_regions(regions, pid)
        except Exception as exc:  # a single process must never abort the whole run
            errors.append(
                AnalysisError(
                    component="go_runtime.pclntab",
                    message=f"pclntab scan failed: {exc}",
                    pid=pid,
                    reason=FailureReason.INTERNAL_ERROR,
                )
            )
            return GoDetectionResult(runtime=None, pclntab_candidates=[], moduledata_candidates=[], errors=errors)

        best_pclntab = _select_best_pclntab_candidate(pclntab_candidates)
        if best_pclntab is None:
            return GoDetectionResult(
                runtime=None,
                pclntab_candidates=pclntab_candidates,
                moduledata_candidates=[],
                errors=errors,
            )

        version_estimate = self._version_detector.detect_from_magic(best_pclntab.magic) if best_pclntab.detection_status == PclntabDetectionStatus.MAGIC_DETECTED else None
        if version_estimate is None:
            # Structural-only candidate: no recognized magic, so no version
            # range can be claimed beyond "a Go runtime was structurally
            # plausible" - never invent a version here.
            version_estimate = self._version_detector.detect_from_magic(best_pclntab.magic or -1)

        moduledata_candidates: list[ModuledataCandidate] = []
        best_moduledata: ModuledataCandidate | None = None
        if best_pclntab.magic is not None:
            moduledata_parser = ModuledataParser(reader, pointer_size)
            try:
                moduledata_candidates = moduledata_parser.find_candidates(
                    regions, pid, best_pclntab.address, best_pclntab.magic
                )
            except Exception as exc:
                errors.append(
                    AnalysisError(
                        component="go_runtime.moduledata",
                        message=f"moduledata scan failed: {exc}",
                        pid=pid,
                        reason=FailureReason.INTERNAL_ERROR,
                    )
                )
            best_moduledata = _select_best_moduledata_candidate(moduledata_candidates)
            if best_moduledata is not None:
                version_estimate = self._version_detector.refine_with_moduledata_layout(
                    version_estimate, best_moduledata.layout_id or ""
                )

        runtime = _build_go_runtime(
            pid=pid,
            architecture=architecture,
            pointer_size=pointer_size,
            pclntab=best_pclntab,
            moduledata=best_moduledata,
            version_estimate=version_estimate,
        )

        return GoDetectionResult(
            runtime=runtime,
            pclntab_candidates=pclntab_candidates,
            moduledata_candidates=moduledata_candidates,
            errors=errors,
        )


def _select_best_pclntab_candidate(candidates: list[PclntabCandidate]) -> PclntabCandidate | None:
    """Prefer a magic-validated candidate; fall back to a structural one.

    Never "silently select the first one" (approved plan Section 11): among
    equally-ranked candidates, the one found first is used only because no
    other evidence distinguishes them, and every candidate (chosen or not)
    remains available in the returned candidate list.
    """
    validated = [c for c in candidates if not c.rejected and c.detection_status == PclntabDetectionStatus.MAGIC_DETECTED]
    if validated:
        return validated[0]
    structural = [
        c for c in candidates if not c.rejected and c.detection_status == PclntabDetectionStatus.MAGIC_NOT_DETECTED_STRUCTURAL_CANDIDATE
    ]
    if structural:
        return structural[0]
    return None


def _select_best_moduledata_candidate(candidates: list[ModuledataCandidate]) -> ModuledataCandidate | None:
    validated = [c for c in candidates if not c.rejected]
    return validated[0] if validated else None


def _build_go_runtime(
    pid: int,
    architecture: str,
    pointer_size: int,
    pclntab: PclntabCandidate,
    moduledata: ModuledataCandidate | None,
    version_estimate,
) -> GoRuntime:
    # Deterministic (address-derived), matching every other artifact id in
    # the project (STR-/FUNC-/PCLNTAB-/MODULEDATA- are all sequence- or
    # address-based, never random) - Phase 6H's full-pipeline determinism
    # check found this previously used uuid.uuid4(), which produced a
    # different runtime_id (and therefore a different value embedded in
    # every string/function provenance's related_artifacts list) on every
    # run against identical evidence, breaking reproducibility (CLAUDE.md
    # section 34). At most one GoRuntime is ever built per (pid, pclntab
    # address), so this remains collision-free.
    runtime_id = f"GORUNTIME-{pid}-{pclntab.address:x}"

    provenance = [
        ArtifactProvenance(
            artifact_id=pclntab.candidate_id,
            artifact_type="pclntab",
            analyzer="go_runtime.pclntab.PclntabParser",
            extraction_method=pclntab.detection_status.value,
            confidence=pclntab.confidence,
            pid=pid,
            virtual_address=pclntab.address_hex,
            memory_region=pclntab.region_source,
        )
    ]

    confidence = Confidence.MEDIUM if pclntab.detection_status == PclntabDetectionStatus.MAGIC_DETECTED else Confidence.LOW
    validation_errors = list(pclntab.validation_errors)

    # GoRuntime.go_version reports the most precise value the evidence
    # actually supports: an exact version if one is ever pinned down (not
    # currently possible from pcHeader/moduledata alone), otherwise the
    # version *range* string (e.g. "1.20+", later narrowed to "1.22+") -
    # never invented patch-level precision (approved plan Section 7).
    reported_go_version = version_estimate.version or version_estimate.version_range
    if reported_go_version == "unknown":
        reported_go_version = None

    runtime = GoRuntime(
        pid=pid,
        architecture=architecture,
        go_version=reported_go_version,
        go_version_confidence=version_estimate.confidence,
        pclntab_address=pclntab.address,
        pclntab_size=None,  # not computable from pcHeader fields alone - see docs/architecture/go-runtime.md
        pc_header_address=pclntab.address,
        confidence=confidence,
        validation_errors=validation_errors,
        provenance=provenance,
        runtime_id=runtime_id,
    )

    if moduledata is not None and moduledata.fields is not None:
        fields = moduledata.fields
        runtime.moduledata_address = moduledata.address
        runtime.text_start = fields.text
        runtime.text_end = fields.etext
        runtime.data_start = fields.data
        runtime.data_end = fields.edata
        runtime.bss_start = fields.bss
        runtime.bss_end = fields.ebss
        runtime.types_start = fields.types
        runtime.types_end = fields.etypes
        if fields.rodata is not None:
            runtime.rodata_start = fields.rodata
            # moduledata has no explicit "erodata" field in any verified
            # layout (see docs/architecture/go-runtime.md) - left null
            # rather than guessed.
            runtime.rodata_end = None
        runtime.typelinks_start = fields.typelinks_ptr
        runtime.typelinks_end = fields.typelinks_ptr + fields.typelinks_len * _TYPELINKS_ELEMENT_SIZE
        runtime.itablinks_start = fields.itablinks_ptr
        runtime.itablinks_end = fields.itablinks_ptr + fields.itablinks_len * pointer_size

        runtime.ftab_address = fields.ftab_ptr
        runtime.ftab_length = fields.ftab_len
        runtime.funcnametab_address = fields.funcnametab_ptr
        runtime.cutab_address = fields.cutab_ptr
        runtime.filetab_address = fields.filetab_ptr
        runtime.pctab_address = fields.pctab_ptr
        runtime.pclntable_address = fields.pclntable_ptr
        runtime.gofunc_address = fields.gofunc

        runtime.provenance.append(
            ArtifactProvenance(
                artifact_id=moduledata.candidate_id,
                artifact_type="moduledata",
                analyzer="go_runtime.moduledata.ModuledataParser",
                extraction_method="pcHeader_pointer_anchor_scan",
                confidence=moduledata.confidence,
                pid=pid,
                virtual_address=moduledata.address_hex,
                related_artifacts=[pclntab.candidate_id],
            )
        )
        runtime.confidence = Confidence.HIGH
    elif moduledata is not None:
        runtime.validation_errors.extend(moduledata.validation_errors)

    return runtime
