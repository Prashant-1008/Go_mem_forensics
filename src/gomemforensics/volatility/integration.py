"""Stable, OS-agnostic facade over Volatility 3.

Hides every Volatility-specific construction detail (contexts, automagic,
layer stacking, plugin construction - see :mod:`gomemforensics.volatility.runner`
and docs/architecture/volatility3-integration.md) behind six operations:
``initialize()``, ``detect_os()``, ``detect_architecture()``,
``enumerate_processes()``, ``get_process_memory(pid)``, and (Phase 2)
``get_process_regions(pid)``.

No Go-specific logic lives here - the Go runtime detection layer
(:mod:`gomemforensics.go_runtime`) consumes only ``MemoryReader`` and
``list[MemoryRegion]``, never anything Volatility-specific.

Every Volatility API referenced here is verified against the installed
volatility3==2.28.2 source; see
docs/architecture/volatility3-integration.md for exact import paths and
source locations.
"""

from __future__ import annotations

from dataclasses import dataclass
from importlib import metadata as importlib_metadata
from pathlib import Path
from typing import TYPE_CHECKING

from gomemforensics.common.logging import get_logger
from gomemforensics.common.memory import MemoryAccessError, MemoryReader, MemoryRegion
from gomemforensics.common.models import AnalysisError, FailureReason, ProcessInfo
from gomemforensics.volatility.runner import VolatilityInitializationError, VolatilityRunner

if TYPE_CHECKING:
    from volatility3.framework.interfaces.context import ContextInterface
    from volatility3.framework.interfaces.layers import TranslationLayerInterface
    from volatility3.framework.interfaces.plugins import PluginInterface

logger = get_logger("volatility.integration")


# ---------------------------------------------------------------------------
# Dependency probing (Phase 0 behavior, unchanged)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class DependencyStatus:
    """Result of probing a single optional/required dependency."""

    name: str
    installed: bool
    version: str | None
    error: str | None = None


@dataclass(frozen=True)
class VolatilityAvailability:
    """Combined dependency probe result for the CLI ``info`` command."""

    volatility3: DependencyStatus
    capstone: DependencyStatus


def _probe(module_name: str, distribution_name: str) -> DependencyStatus:
    try:
        __import__(module_name)
    except ImportError as exc:
        return DependencyStatus(name=distribution_name, installed=False, version=None, error=str(exc))

    try:
        version = importlib_metadata.version(distribution_name)
    except importlib_metadata.PackageNotFoundError:
        version = None

    return DependencyStatus(name=distribution_name, installed=True, version=version)


def probe_dependencies() -> VolatilityAvailability:
    """Report whether Volatility 3 and Capstone are installed and importable.

    Safe to call at any time: it never raises, and never touches a memory
    image or any Volatility API beyond the top-level import.
    """
    return VolatilityAvailability(
        volatility3=_probe("volatility3", "volatility3"),
        capstone=_probe("capstone", "capstone"),
    )


# ---------------------------------------------------------------------------
# OS / architecture normalization
# ---------------------------------------------------------------------------

#: Verified raw values (docs/architecture/volatility3-integration.md section 10):
#: only "Intel32"/"Intel64" have ever been observed from this Volatility
#: version, since no ARM/AArch64 layer exists in volatility3==2.28.2. The
#: ARM64/AArch64 entries are forward-compatible only - never exercised by
#: this Volatility version - and must not be read as a claim of support.
_ARCHITECTURE_NORMALIZATION = {
    "Intel64": "x86_64",
    "Intel32": "x86",
    "ARM64": "arm64",
    "AArch64": "arm64",
}


def _normalize_architecture(raw: str | None) -> str:
    if raw is None:
        return "unknown"
    return _ARCHITECTURE_NORMALIZATION.get(raw, "unknown")


def _normalize_os(raw: str | None) -> str:
    if raw is None:
        return "unknown"
    normalized = raw.strip().lower()
    if normalized == "windows":
        return "windows"
    if normalized == "linux":
        return "linux"
    return "unknown"


def _resolve_os(metadata_os: str | None, os_kind: str | None) -> str:
    """Resolve the final OS value, preferring the kernel layer's own
    metadata but falling back to which OS-specific plugin actually
    constructed successfully when the metadata gives nothing usable.

    The kernel layer's ``"os"`` metadata key is the primary signal
    (CLAUDE.md section 40: never assumed from which construction attempt
    happened to succeed) - but Phase 7B's first real-memory validation
    (a genuine Windows crash-dump image, ``WindowsCrashDump64Layer``)
    found this key stays ``"Unknown"`` for that physical-layer type even
    though Windows-specific plugin construction and kernel-symbol
    resolution both genuinely succeeded (245 real Windows processes were
    correctly enumerated). ``os_kind`` (``"windows"``/``"linux"``, set in
    :meth:`VolatilityIntegration.initialize` from which OS-specific
    plugin actually satisfied its requirements) is a real, independent,
    already-verified signal - not a guess - so it is used only as a
    fallback, never overriding a metadata value that already resolved.
    """
    normalized = _normalize_os(metadata_os)
    if normalized != "unknown":
        return normalized
    if os_kind in ("windows", "linux"):
        return os_kind
    return "unknown"


# ---------------------------------------------------------------------------
# Process memory reader
# ---------------------------------------------------------------------------


class VolatilityMemoryReader(MemoryReader):
    """MemoryReader backed by a single Volatility translation layer.

    Always reads with ``pad=False`` (docs/architecture/volatility3-integration.md
    section 9), so unmapped/invalid memory raises :class:`MemoryAccessError`
    rather than silently returning zero-filled bytes - "invalid" and "really
    zero" must stay distinguishable. This never falls back to a physical
    layer: it only ever reads the single (process-virtual) layer it was
    constructed with. There is no write method (see
    :class:`gomemforensics.common.memory.MemoryReader`).
    """

    def __init__(self, layer: "TranslationLayerInterface", pointer_size: int) -> None:
        self._layer = layer
        self._pointer_size = pointer_size

    @property
    def pointer_size(self) -> int:
        return self._pointer_size

    def is_valid(self, address: int) -> bool:
        try:
            return bool(self._layer.is_valid(address))
        except Exception:
            # A malformed/unmapped address should read as "not valid", not
            # crash the caller - callers that need to see the underlying
            # cause should call read() instead, which raises with detail.
            return False

    def read(self, address: int, length: int) -> bytes:
        from volatility3.framework import exceptions as vol_exceptions

        try:
            return self._layer.read(address, length, pad=False)
        except vol_exceptions.InvalidAddressException as exc:
            raise MemoryAccessError(
                f"Invalid/unmapped address 0x{address:x} (length {length}): {exc}"
            ) from exc
        except vol_exceptions.LayerException as exc:
            raise MemoryAccessError(f"Layer error reading 0x{address:x} (length {length}): {exc}") from exc


# ---------------------------------------------------------------------------
# Integration facade
# ---------------------------------------------------------------------------


class VolatilityIntegrationError(Exception):
    """Raised when a :class:`VolatilityIntegration` method is misused.

    In particular, calling any accessor before :meth:`VolatilityIntegration.initialize`
    has succeeded.
    """


class VolatilityIntegration:
    """Stable, OS-agnostic facade over Volatility 3 for GoMemForensics."""

    def __init__(self) -> None:
        self._context: "ContextInterface | None" = None
        self._plugin: "PluginInterface | None" = None
        self._kernel_module_name: str | None = None
        self._os_kind: str | None = None  # "windows" or "linux" - which pslist plugin succeeded
        self._os: str = "unknown"
        self._architecture: str = "unknown"
        self._pointer_size: int = 8
        #: pid -> raw Volatility process object (EPROCESS/task_struct), so
        #: get_process_memory() doesn't need to re-enumerate every call.
        self._raw_processes: dict[int, object] = {}

    def initialize(self, image_path: Path) -> None:
        """Determine which supported OS this image belongs to and set up access to it.

        Tries constructing the Windows, then the Linux, process-listing
        plugin against the image. Volatility's own requirement-satisfaction
        machinery (layer stacking + OS-specific symbol resolution) is the
        actual detection mechanism - whichever OS's plugin can be fully
        constructed against this image determines the detected OS; this is
        then double-confirmed by reading the real ``os``/``architecture``
        values from the resulting kernel layer's metadata (never assumed
        from which attempt happened to succeed).

        Raises:
            VolatilityInitializationError: if the image cannot be processed
                as any supported OS (unsupported/corrupted image, or an OS
                this project does not target).
        """
        from volatility3.plugins.linux import pslist as linux_pslist
        from volatility3.plugins.windows import pslist as windows_pslist

        runner = VolatilityRunner(image_path)
        attempts = (
            ("windows", windows_pslist.PsList),
            ("linux", linux_pslist.PsList),
        )

        failures: list[str] = []
        for os_label, plugin_class in attempts:
            try:
                result = runner.construct_plugin(plugin_class)
            except VolatilityInitializationError as exc:
                failures.append(f"{os_label}: {exc}")
                logger.debug("OS probe failed for %s: %s", os_label, exc)
                continue

            self._context = result.context
            self._plugin = result.plugin
            self._os_kind = os_label
            self._resolve_system_info()
            logger.info(
                "Volatility initialized for %s: os=%s architecture=%s",
                image_path,
                self._os,
                self._architecture,
            )
            return

        raise VolatilityInitializationError(
            "Could not initialize Volatility against this image for any supported OS "
            "(Windows, Linux). " + " | ".join(failures)
        )

    def _resolve_system_info(self) -> None:
        assert self._context is not None and self._plugin is not None
        kernel_module_name = self._plugin.config["kernel"]
        self._kernel_module_name = kernel_module_name
        kernel_module = self._context.modules[kernel_module_name]
        kernel_layer = self._context.layers[kernel_module.layer_name]

        self._os = _resolve_os(kernel_layer.metadata.get("os"), self._os_kind)
        self._architecture = _normalize_architecture(kernel_layer.metadata.get("architecture"))

        try:
            self._pointer_size = max(4, kernel_layer.bits_per_register // 8)
        except AttributeError:
            self._pointer_size = 8

    def _require_initialized(self) -> None:
        if self._context is None or self._plugin is None:
            raise VolatilityIntegrationError(
                "VolatilityIntegration.initialize() must succeed before this call."
            )

    def detect_os(self) -> str:
        """Return the detected OS: ``"windows"``, ``"linux"``, or ``"unknown"``."""
        self._require_initialized()
        return self._os

    def detect_architecture(self) -> str:
        """Return the detected architecture: ``"x86_64"``, ``"x86"``, ``"arm64"``, or ``"unknown"``."""
        self._require_initialized()
        return self._architecture

    def enumerate_processes(self) -> tuple[list[ProcessInfo], list[AnalysisError]]:
        """Enumerate processes, normalized into :class:`ProcessInfo`.

        One malformed process never aborts the whole enumeration: failures
        are recorded as :class:`AnalysisError` entries and that process is
        skipped (CLAUDE.md section 24, "recover -> record error -> continue").
        """
        self._require_initialized()
        if self._os_kind == "windows":
            return self._enumerate_windows_processes()
        if self._os_kind == "linux":
            return self._enumerate_linux_processes()
        raise VolatilityIntegrationError(f"Unknown OS kind: {self._os_kind!r}")

    def _enumerate_windows_processes(self) -> tuple[list[ProcessInfo], list[AnalysisError]]:
        from volatility3.framework import exceptions as vol_exceptions
        from volatility3.plugins.windows import pslist as windows_pslist

        processes: list[ProcessInfo] = []
        errors: list[AnalysisError] = []
        self._raw_processes.clear()

        try:
            proc_iter = list(
                windows_pslist.PsList.list_processes(self._context, self._kernel_module_name)
            )
        except Exception as exc:
            errors.append(
                AnalysisError(
                    component="volatility.integration.enumerate_processes",
                    message=f"Windows process listing failed entirely: {exc}",
                    recoverable=False,
                    reason=FailureReason.OS_PROCESS_DISCOVERY_FAILED,
                )
            )
            return processes, errors

        for proc in proc_iter:
            pid: int | None = None
            try:
                pid = int(proc.UniqueProcessId)
                ppid = int(proc.InheritedFromUniqueProcessId)
                name = str(
                    proc.ImageFileName.cast(
                        "string", max_length=proc.ImageFileName.vol.count, errors="replace"
                    )
                ).strip() or None

                try:
                    create_time_value = proc.get_create_time()
                    create_time = str(create_time_value) if create_time_value else None
                except Exception:
                    create_time = None

                # Verified real pattern (framework/plugins/windows/pstree.py):
                # PEB access can legitimately fail (paged-out/invalid PEB).
                try:
                    executable_path = str(
                        proc.get_peb().ProcessParameters.ImagePathName.get_string()
                    ) or None
                except vol_exceptions.InvalidAddressException:
                    executable_path = None
                except Exception:
                    executable_path = None

                memory_layer_available = False
                try:
                    layer_name = proc.add_process_layer()
                    memory_layer_available = bool(layer_name)
                    if memory_layer_available:
                        self._raw_processes[pid] = proc
                except vol_exceptions.InvalidAddressException:
                    memory_layer_available = False

                processes.append(
                    ProcessInfo(
                        pid=pid,
                        ppid=ppid,
                        name=name,
                        executable_path=executable_path,
                        architecture=self._architecture,
                        os=self._os,
                        create_time=create_time,
                        memory_layer_available=memory_layer_available,
                    )
                )
            except vol_exceptions.InvalidAddressException as exc:
                errors.append(
                    AnalysisError(
                        component="volatility.integration.enumerate_processes",
                        message=f"Invalid address while reading a Windows process: {exc}",
                        pid=pid,
                        reason=FailureReason.ADDRESS_SPACE_UNAVAILABLE,
                    )
                )
            except Exception as exc:  # a single malformed process must not abort the run
                errors.append(
                    AnalysisError(
                        component="volatility.integration.enumerate_processes",
                        message=f"Malformed Windows process skipped: {exc}",
                        pid=pid,
                        reason=FailureReason.INSUFFICIENT_EVIDENCE,
                    )
                )

        processes.sort(key=lambda p: p.pid)
        return processes, errors

    def _enumerate_linux_processes(self) -> tuple[list[ProcessInfo], list[AnalysisError]]:
        from volatility3.framework import exceptions as vol_exceptions
        from volatility3.plugins.linux import pslist as linux_pslist

        processes: list[ProcessInfo] = []
        errors: list[AnalysisError] = []
        self._raw_processes.clear()

        try:
            task_iter = list(
                linux_pslist.PsList.list_tasks(self._context, self._kernel_module_name)
            )
        except Exception as exc:
            errors.append(
                AnalysisError(
                    component="volatility.integration.enumerate_processes",
                    message=f"Linux process listing failed entirely: {exc}",
                    recoverable=False,
                    reason=FailureReason.OS_PROCESS_DISCOVERY_FAILED,
                )
            )
            return processes, errors

        for task in task_iter:
            pid: int | None = None
            try:
                fields = linux_pslist.PsList.get_task_fields(task)
                pid = int(fields.user_pid)
                ppid = int(fields.user_ppid) if fields.user_ppid is not None else None
                name = fields.name or None
                create_time = str(fields.creation_time) if fields.creation_time else None
                executable_path = _linux_executable_path(task)

                memory_layer_available = False
                try:
                    layer_name = task.add_process_layer()
                    memory_layer_available = bool(layer_name)
                    if memory_layer_available:
                        self._raw_processes[pid] = task
                except vol_exceptions.InvalidAddressException:
                    memory_layer_available = False

                processes.append(
                    ProcessInfo(
                        pid=pid,
                        ppid=ppid,
                        name=name,
                        executable_path=executable_path,
                        architecture=self._architecture,
                        os=self._os,
                        create_time=create_time,
                        memory_layer_available=memory_layer_available,
                    )
                )
            except vol_exceptions.InvalidAddressException as exc:
                errors.append(
                    AnalysisError(
                        component="volatility.integration.enumerate_processes",
                        message=f"Invalid address while reading a Linux task: {exc}",
                        pid=pid,
                        reason=FailureReason.ADDRESS_SPACE_UNAVAILABLE,
                    )
                )
            except Exception as exc:  # a single malformed task must not abort the run
                errors.append(
                    AnalysisError(
                        component="volatility.integration.enumerate_processes",
                        message=f"Malformed Linux task skipped: {exc}",
                        pid=pid,
                        reason=FailureReason.INSUFFICIENT_EVIDENCE,
                    )
                )

        processes.sort(key=lambda p: p.pid)
        return processes, errors

    def get_process_memory(self, pid: int) -> MemoryReader | None:
        """Return a read-only :class:`MemoryReader` over ``pid``'s virtual address space.

        Returns ``None`` if the process is unknown to this integration
        instance (call :meth:`enumerate_processes` first) or has no
        accessible memory layer - both are normal, expected outcomes (a
        paged-out DTB, a terminated process, a kernel thread), not errors.
        """
        self._require_initialized()
        proc = self._raw_processes.get(pid)
        if proc is None:
            return None

        from volatility3.framework import exceptions as vol_exceptions

        try:
            layer_name = proc.add_process_layer()
        except vol_exceptions.InvalidAddressException:
            return None
        if not layer_name:
            return None

        layer = self._context.layers[layer_name]
        return VolatilityMemoryReader(layer, pointer_size=self._pointer_size)

    def get_process_regions(self, pid: int) -> list[MemoryRegion]:
        """Return normalized memory regions for ``pid`` (Windows VAD / Linux VMA).

        Returns an empty list if the process is unknown to this integration
        instance or its region information is inaccessible - a normal,
        expected outcome (matches :meth:`get_process_memory`'s policy), not
        an error. Callers (the Go runtime detection layer) never see
        Volatility's VAD/VMA objects directly - only this normalized,
        OS-independent :class:`MemoryRegion` list.
        """
        self._require_initialized()
        proc = self._raw_processes.get(pid)
        if proc is None:
            return []

        if self._os_kind == "windows":
            return self._windows_process_regions(pid, proc)
        if self._os_kind == "linux":
            return self._linux_process_regions(proc)
        return []

    def _windows_process_regions(self, pid: int, proc: object) -> list[MemoryRegion]:
        from volatility3.framework import exceptions as vol_exceptions
        from volatility3.plugins.windows.vadinfo import VadInfo, winnt_protections

        protect_values = None
        try:
            kernel_module = self._context.modules[self._kernel_module_name]
            protect_values = VadInfo.protect_values(
                self._context, kernel_module.layer_name, kernel_module.symbol_table_name
            )
        except Exception as exc:
            logger.debug("pid=%s: could not resolve VAD protection value table: %s", pid, exc)

        try:
            vad_root = proc.get_vad_root()
        except (vol_exceptions.InvalidAddressException, AttributeError):
            return []

        regions: list[MemoryRegion] = []
        for vad in vad_root.traverse():
            try:
                start = int(vad.get_start())
                end = int(vad.get_end())
            except vol_exceptions.InvalidAddressException:
                continue
            if end <= start:
                continue

            readable, writable, executable = True, False, False
            if protect_values is not None:
                try:
                    protection = vad.get_protection(protect_values, winnt_protections)
                    readable, writable, executable = _parse_windows_protection(protection)
                except Exception:
                    pass  # keep the conservative default above

            regions.append(
                MemoryRegion(
                    start=start, end=end, readable=readable, writable=writable, executable=executable, source="vad"
                )
            )
        return regions

    def _linux_process_regions(self, task: object) -> list[MemoryRegion]:
        from volatility3.framework import exceptions as vol_exceptions

        mm = getattr(task, "mm", None)
        if not mm or not mm.is_readable():
            return []

        try:
            vma_iter = mm.get_vma_iter()
        except Exception:
            return []

        regions: list[MemoryRegion] = []
        for vma in vma_iter:
            try:
                start = int(vma.vm_start)
                end = int(vma.vm_end)
            except vol_exceptions.InvalidAddressException:
                continue
            if end <= start:
                continue

            try:
                protection = vma.get_protection()
            except Exception:
                protection = ""

            regions.append(
                MemoryRegion(
                    start=start,
                    end=end,
                    readable="r" in protection,
                    writable="w" in protection,
                    executable="x" in protection,
                    source="vma",
                )
            )
        return regions


#: Windows VAD protection constant names implying each permission bit.
#: Verified from volatility3.plugins.windows.vadinfo.winnt_protections.
_WINDOWS_READABLE_FLAGS = {
    "PAGE_READONLY", "PAGE_READWRITE", "PAGE_WRITECOPY",
    "PAGE_EXECUTE_READ", "PAGE_EXECUTE_READWRITE", "PAGE_EXECUTE_WRITECOPY",
}
_WINDOWS_WRITABLE_FLAGS = {
    "PAGE_READWRITE", "PAGE_WRITECOPY", "PAGE_EXECUTE_READWRITE", "PAGE_EXECUTE_WRITECOPY",
}
_WINDOWS_EXECUTABLE_FLAGS = {
    "PAGE_EXECUTE", "PAGE_EXECUTE_READ", "PAGE_EXECUTE_READWRITE", "PAGE_EXECUTE_WRITECOPY",
}


def _parse_windows_protection(protection: str) -> tuple[bool, bool, bool]:
    """Parse a ``VAD.get_protection()`` pipe-joined string into (readable, writable, executable)."""
    if not protection:
        # Could not be determined - default to readable (most VADs are)
        # rather than silently excluding the region from every scan;
        # scans remain bounded regardless by the safety limits in
        # gomemforensics.go_runtime.pclntab/moduledata.
        return True, False, False
    flags = set(protection.split("|"))
    if "PAGE_NOACCESS" in flags:
        return False, False, False
    return bool(flags & _WINDOWS_READABLE_FLAGS), bool(flags & _WINDOWS_WRITABLE_FLAGS), bool(flags & _WINDOWS_EXECUTABLE_FLAGS)


def _linux_executable_path(task: object) -> str | None:
    """Best-effort Linux executable path resolution.

    Built only from verified public methods (docs/architecture/volatility3-integration.md
    section 7): ``mm_struct.exe_file`` -> ``struct_file.get_dentry()`` ->
    ``dentry.path()``. Not provided by ``linux.pslist`` itself; returns
    ``None`` on any failure rather than guessing, since the executable path
    is not always available (paged-out mm, kernel thread, etc.).
    """
    try:
        mm = task.mm  # type: ignore[attr-defined]
        if not mm or not mm.is_readable():
            return None
        if not mm.has_member("exe_file"):
            return None
        exe_file = mm.exe_file
        if not exe_file or not exe_file.is_readable():
            return None
        dentry = exe_file.get_dentry()
        if dentry is None:
            return None
        path = dentry.path()
        return path or None
    except Exception:
        return None
