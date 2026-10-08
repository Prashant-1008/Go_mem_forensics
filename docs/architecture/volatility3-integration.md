# Volatility 3 Integration — Verified API Reference

**Status: Phase 1.** Every API below was read directly from the installed
`volatility3==2.28.2` source at
`.venv/Lib/site-packages/volatility3/` (verified against this exact
version; not from documentation or general knowledge). Nothing in this
document is used in code until it is verified here. Sections marked
**"not found in this version"** are gaps this project cannot rely on.

Plugin modules must always be imported as `volatility3.plugins.<os>.<name>`
(never `volatility3.framework.plugins.<os>.<name>`) — `volatility3/plugins/__init__.py`
redirects `__path__` to the real files under `framework/plugins/`, and
`automagic.choose_automagic` filters automagics by checking whether
`plugin.__module__` contains an OS category string (`"windows"`, `"linux"`,
`"mac"` — from `constants.OS_CATEGORIES`), which only works through the
`volatility3.plugins.*` import path.

## 1. Context construction and configuration

**Import:** `from volatility3.framework import contexts` → `contexts.Context`
(`framework/contexts/__init__.py`)

```python
class Context(interfaces.context.ContextInterface):
    def __init__(self) -> None: ...
    @property
    def config(self) -> interfaces.configuration.HierarchicalDict: ...
    @property
    def layers(self) -> interfaces.layers.LayerContainer: ...
    @property
    def modules(self) -> interfaces.context.ModuleContainer: ...
    @property
    def symbol_space(self) -> interfaces.symbols.SymbolSpaceInterface: ...
```

The image location is set on the config tree, not on `Context` directly:

```python
context.config["automagic.LayerStacker.single_location"] = single_location
```

## 2. Automagic

**Import:** `from volatility3.framework import automagic`
(`framework/automagic/__init__.py`)

```python
def available(context: ContextInterface) -> List[AutomagicInterface]: ...

def choose_automagic(
    automagics: List[Type[AutomagicInterface]],
    plugin: Type[PluginInterface],
) -> List[Type[AutomagicInterface]]: ...
```

`automagic.run(...)` is called internally by `construct_plugin` (§3) — this
project never calls it directly.

Relevant concrete automagics discovered by `available()` (all under
`volatility3.framework.automagic.*`): `LayerStacker` (stacks the raw file
into a typed translation layer), `KernelPDBScanner` (Windows kernel symbol
resolution via PDB), `LinuxSymbolFinder` (Linux kernel symbol resolution via
banner scan), `ConstructionMagic`, `KernelModule` (resolves a plugin's
`kernel` `ModuleRequirement`).

**Verified OS-detection mechanism** (`framework/automagic/stacker.py`,
`LayerStacker.create_stackers_list`): if
`context.config["automagic.LayerStacker.stackers"]` is never set, `stack_set`
is **not filtered** and every registered `StackerLayerInterface` subclass
(Windows/Linux/Mac Intel stackers) is tried against the image. This project
relies on that default (unfiltered) behavior rather than pre-selecting an
OS, since pre-selecting would defeat the purpose of OS detection.

## 3. End-to-end plugin construction (verified against `cli/__init__.py`, full 943-line file read)

**`construct_plugin`** — `from volatility3.framework import plugins as vol_plugins`
(`framework/plugins/__init__.py`, full source read):

```python
def construct_plugin(
    context: interfaces.context.ContextInterface,
    automagics: List[interfaces.automagic.AutomagicInterface],
    plugin: Type[interfaces.plugins.PluginInterface],
    base_config_path: str,
    progress_callback: constants.ProgressCallback,
    open_method: Type[interfaces.plugins.FileHandlerInterface],
) -> interfaces.plugins.PluginInterface:
```

Verified behavior (read from the actual body): calls
`automagic.run(automagics, context, plugin, base_config_path, progress_callback=...)`,
then `plugin.unsatisfied(context, plugin_config_path)`; if non-empty, raises
`exceptions.UnsatisfiedException(unsatisfied)`. Otherwise constructs
`plugin(context, plugin_config_path, progress_callback=progress_callback)`.
`open_method` is only used if truthy (`if open_method:`), so **`open_method=None`
is safe** for plugins that don't need file-dumping (pslist doesn't, for our use).

**Verified minimal usage pattern** (this project's actual pattern, built from
`cli/__init__.py`'s own sequence at lines ~316–523):

```python
from volatility3.framework import automagic, contexts, exceptions as vol_exceptions
from volatility3.framework import plugins as vol_plugins
from volatility3.framework.configuration import requirements
import volatility3.plugins
from volatility3 import framework

framework.import_files(volatility3.plugins, True)  # discover/import all plugin modules once

context = contexts.Context()
single_location = requirements.URIRequirement.location_from_file(str(image_path))
context.config["automagic.LayerStacker.single_location"] = single_location

available_automagics = automagic.available(context)
chosen_automagics = automagic.choose_automagic(available_automagics, plugin_class)

constructed = vol_plugins.construct_plugin(
    context, chosen_automagics, plugin_class, "plugins",
    progress_callback=None, open_method=None,
)
```

`requirements.URIRequirement.location_from_file` — verified to exist as a
classmethod on `URIRequirement` (`framework/configuration/requirements.py`).

`framework.import_files(base_module, ignore_errors: bool = False) -> List[str]`
and `framework.list_plugins() -> Dict[str, Type[PluginInterface]]` — both
verified present in `framework/__init__.py`.

## 4. PluginInterface

**Import:** `from volatility3.framework import interfaces` →
`interfaces.plugins.PluginInterface` (`framework/interfaces/plugins.py`)

```python
class PluginInterface(ConfigurableInterface, VersionableInterface, metaclass=ABCMeta):
    def __init__(self, context, config_path: str, progress_callback=None) -> None: ...
    @classmethod
    def get_requirements(cls) -> List[RequirementInterface]: ...
    @abstractmethod
    def run(self) -> interfaces.renderers.TreeGrid: ...
```

Never instantiate a plugin class directly — always via `construct_plugin`
(§3), since `__init__` requires `context.config` at `config_path` to already
be fully populated by automagic.

## 5. TreeGrid

**Import:** `from volatility3.framework import renderers` → `renderers.TreeGrid`
(`framework/renderers/__init__.py`)

```python
class TreeGrid(interfaces.renderers.TreeGrid):
    def __init__(self, columns: List[Tuple[str, BaseTypes]], generator: Optional[Iterable[Tuple[int, Tuple]]]) -> None: ...
    def populate(self, function=None, initial_accumulator=None, fail_on_errors=True) -> Optional[Exception]: ...
    @property
    def columns(self) -> List[Column]: ...
```

**This project does not use `TreeGrid`/`run()` at all in Phase 1.** Process
enumeration instead calls the plugins' own documented classmethods directly
(`PsList.list_processes` / `PsList.list_tasks`, §6/§7), which yield live
runtime objects (`EPROCESS`/`task_struct`) rather than pre-rendered rows —
this gives direct access to `add_process_layer()` and other per-object
methods that a `TreeGrid` row would have already discarded. `TreeGrid` is
recorded here because `PluginInterface.run()` must return one, but
GoMemForensics' Phase 1 JSON output is built directly from the normalized
`ProcessInfo` model, not from a `TreeGrid`.

No generic JSON-emitting renderer exists under `framework/renderers/`
(confirmed by directory listing — only `__init__.py` and `format_hints.py`);
the only JSON renderer (`JsonRenderer`) lives in `volatility3/cli/text_renderer.py`,
which is CLI-only code this project does not depend on.

## 6. Windows process enumeration

**Import:** `from volatility3.plugins.windows import pslist`
(file on disk: `framework/plugins/windows/pslist.py`)

```python
class PsList(interfaces.plugins.PluginInterface, timeliner.TimeLinerInterface):
    @classmethod
    def get_requirements(cls): ...  # includes ModuleRequirement(name="kernel", architectures=["Intel32","Intel64"])

    @classmethod
    def list_processes(
        cls, context, kernel_module_name: str,
        filter_func: Callable[[ObjectInterface], bool] = lambda _: False,
    ) -> Iterator["extensions.EPROCESS"]: ...
```

**Verified field-access pattern** (`_generator()` and `pstree.py`, full read):

```python
kernel = context.modules[kernel_module_name]
for proc in PsList.list_processes(context, kernel_module_name):
    pid = proc.UniqueProcessId
    ppid = proc.InheritedFromUniqueProcessId
    name = proc.ImageFileName.cast("string", max_length=proc.ImageFileName.vol.count, errors="replace")
    create_time = proc.get_create_time()
    try:
        image_path = proc.get_peb().ProcessParameters.ImagePathName.get_string()
    except exceptions.InvalidAddressException:
        image_path = None  # verified real pattern from framework/plugins/windows/pstree.py
```

**Per-process memory layer** — `EPROCESS.add_process_layer()`
(`framework/symbols/windows/extensions/__init__.py`, full body read):

```python
def add_process_layer(self, config_prefix=None, preferred_name=None) -> str: ...
```

Returns a layer name string (e.g. `"<parent_layer>_Process<pid>"`), looked
up via `context.layers[layer_name]`. **Can raise `exceptions.InvalidAddressException`**
(does not swallow it — verified from the docstring at `get_peb()`'s call
site and the method body itself: it is not wrapped in try/except).

**Getting the kernel layer / OS / architecture** (verified via
`context.modules`, `ModuleInterface.layer_name` in `framework/interfaces/context.py`,
and the layer's `metadata` property in `framework/interfaces/layers.py`):

```python
kernel_module_name = constructed.config["kernel"]       # verified: pslist.py uses self.config["kernel"]
kernel_module = constructed.context.modules[kernel_module_name]
kernel_layer_name = kernel_module.layer_name             # ModuleInterface.layer_name -> self.config["layer_name"]
kernel_layer = constructed.context.layers[kernel_layer_name]
os_name = kernel_layer.metadata.get("os", "Unknown")      # set by WindowsIntelStacker/LinuxIntelStacker, etc.
architecture = kernel_layer.metadata.get("architecture", "Unknown")  # "Intel32" / "Intel64"
```

## 7. Linux process enumeration

**Import:** `from volatility3.plugins.linux import pslist`
(file on disk: `framework/plugins/linux/pslist.py`)

```python
class PsList(interfaces.plugins.PluginInterface, timeliner.TimeLinerInterface):
    @classmethod
    def list_tasks(cls, context, vmlinux_module_name: str, filter_func=..., include_threads=False) -> Iterable[ObjectInterface]: ...
    @classmethod
    def get_task_fields(cls, task, decorate_comm: bool = False) -> TaskFields: ...
```

**Verified `TaskFields` construction** (`get_task_fields`, full body read):

```python
name = utility.array_to_string(task.comm)
user_pid = task.tgid          # traditional Linux PID (thread-group id)
user_tid = task.pid           # this kernel's task.pid is actually the thread id
user_ppid = task.get_parent_pid()
creation_time = None
with contextlib.suppress(Exception):
    creation_time = task.get_create_time()
```

**Per-task memory layer** — `task_struct.add_process_layer()`
(`framework/symbols/linux/extensions/__init__.py`, full body read):

```python
def add_process_layer(self, config_prefix=None, preferred_name=None) -> Optional[str]: ...
```

Unlike Windows, **this catches `InvalidAddressException` internally and
returns `None`** rather than raising — verified from the method body
(`except exceptions.InvalidAddressException: return None`).

**Executable path (best-effort, verified real methods only, no custom struct
offsets)** — via `mm_struct.exe_file` → `struct_file.get_dentry()` → `dentry.path()`:

```python
# struct_file.get_dentry() and dentry.path() are real public methods,
# verified in framework/symbols/linux/extensions/__init__.py
mm = task.mm
if mm and mm.is_readable() and mm.has_member("exe_file"):
    exe_file = mm.exe_file
    if exe_file and exe_file.is_readable():
        image_path = exe_file.get_dentry().path()
```

This project wraps the whole chain in a broad `try/except`, returning
`None` on any failure — `pslist` itself does not expose an executable path
column, so this is this project's own best-effort addition built only from
verified public methods, not a Volatility-provided guarantee.

## 8. Existing page-cache / file-dump plugins (recorded for later phases, not used in Phase 1)

- `volatility3.plugins.linux.pagecache` (`framework/plugins/linux/pagecache.py`):
  three plugin classes — `Files`, `InodePages`, `RecoverFs`.
- `volatility3.plugins.windows.dumpfiles` (`framework/plugins/windows/dumpfiles.py`):
  `DumpFiles` plugin class, requires `pslist`/`handles` version requirements.

Neither is invoked by Phase 1 code; recorded here purely so a later phase
doesn't have to re-derive the import paths.

## 9. Reading process memory generically

**Import:** `interfaces.layers.DataLayerInterface` / `TranslationLayerInterface`
(`framework/interfaces/layers.py`)

```python
def read(self, offset: int, length: int, pad: bool = False) -> bytes: ...
def is_valid(self, offset: int, length: int = 1) -> bool: ...
```

If `pad=False` (this project always uses `pad=False` — see §18 "no silent
fallback") and the offset can't be mapped, raises
`exceptions.InvalidAddressException(layer_name, invalid_address, ...)`.
`LayerContainer.read(layer_name, offset, length, pad=False)` is an
equivalent convenience wrapper.

**Verified exception hierarchy** (`framework/exceptions.py`, full read):

```python
class VolatilityException(Exception): ...
class PluginRequirementException(VolatilityException): ...
class LayerException(VolatilityException):
    def __init__(self, layer_name: str, *args) -> None: ...
class InvalidAddressException(LayerException):
    def __init__(self, layer_name: str, invalid_address: int, *args) -> None: ...
class UnsatisfiedException(VolatilityException):
    def __init__(self, unsatisfied: Dict[str, RequirementInterface]) -> None: ...
```

`GoMemForensics`'s `VolatilityMemoryReader` (see `common/memory.py` /
`volatility/integration.py`) catches `InvalidAddressException` and the
broader `LayerException` and re-raises them as this project's own
`gomemforensics.common.memory.MemoryAccessError`, so analyzer code never
needs to import Volatility's exception types directly.

## 10. OS / architecture identification from layer metadata

**Import:** `layer.metadata` property (`framework/interfaces/layers.py`) — a
`ChainMap` that merges a layer's own `_direct_metadata` with every layer it
depends on, down to the base physical layer.

**Verified concrete values** (`framework/layers/intel.py`):

```python
class Intel(linear.LinearlyMappedLayer):
    _direct_metadata = ...{"architecture": "Intel32"}, {"mapped": True}...
class IntelPAE(Intel):
    _direct_metadata = ...{"pae": True}...
class Intel32e(Intel):   # x86-64
    _direct_metadata = ...{"architecture": "Intel64"}...
```

`os` metadata key set only by (`grep`-verified, 4 locations):
`framework/automagic/windows.py` (`"os": "Windows"`),
`framework/automagic/linux.py` (`"os": "Linux"`),
`framework/automagic/mac.py` (`"os": "Mac"` / `"mac"`, inconsistent casing).

**Gap, explicitly verified absent:** no ARM/AArch64 layer implementation
exists anywhere under `framework/layers/` in this installed version — only
Intel (`Intel`, `IntelPAE`, `Intel32e`). `renderers.Disassembly.possible_architectures`
lists `["intel", "intel64", "arm", "arm64"]` but that is a disassembly-hint
enum only, not evidence of ARM layer support. **This means Volatility 3
2.28.2 itself cannot process an ARM64 memory image** — this is not a
GoMemForensics limitation, it is a limitation of the installed Volatility
version, and is documented as such in `docs/supported-platforms/platforms.md`.

GoMemForensics normalizes the raw `metadata["architecture"]` value:
`"Intel64"` → `"x86_64"`, `"Intel32"` → `"x86"`, anything else/absent →
`"unknown"`. No ARM64 value has ever been observed from this Volatility
version, so `"arm64"` normalization exists only as forward-compatible
dead code, not a claim of support.

## Explicitly not found in this version

- No ARM/ARM64 translation layer (§10).
- No standalone, reusable JSON `TreeGrid` renderer outside `volatility3.cli` (§5).
- No reusable concrete `FileHandlerInterface` outside `volatility3.cli`'s
  private nested classes (irrelevant to Phase 1, relevant only if a later
  phase uses `dumpfiles`/`pagecache`'s dump features).
