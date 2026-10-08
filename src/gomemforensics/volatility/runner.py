"""OS-agnostic Volatility 3 context/automagic/plugin construction.

This is the low-level engine: it knows how to take an image path and a
caller-supplied Volatility plugin class and produce a fully-configured,
constructed plugin instance against that image. It contains no OS-specific
plugin *selection* logic and no Go-specific logic whatsoever - the caller
(:mod:`gomemforensics.volatility.integration`) decides which plugin class to
construct and what to do with the result.

Every API used here is verified against the installed volatility3==2.28.2
source; see docs/architecture/volatility3-integration.md for the exact
import paths, signatures, and source locations this implementation is
built from.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Type

from gomemforensics.common.logging import get_logger

if TYPE_CHECKING:
    from volatility3.framework.interfaces.context import ContextInterface
    from volatility3.framework.interfaces.plugins import PluginInterface

logger = get_logger("volatility.runner")

#: Guards against re-running the (moderately expensive) plugin-module
#: discovery/import scan more than once per process.
_plugins_imported = False


def _ensure_plugins_imported() -> None:
    global _plugins_imported
    if _plugins_imported:
        return

    import volatility3.plugins
    from volatility3 import framework

    framework.import_files(volatility3.plugins, True)
    _plugins_imported = True
    logger.debug("Volatility plugin modules discovered and imported.")


class VolatilityInitializationError(Exception):
    """Raised when Volatility cannot process the given image with a given plugin.

    Covers unsatisfied plugin requirements (wrong OS/architecture for the
    requested plugin, corrupted/unsupported image) and any other error
    Volatility's automagic/construction machinery raises. Per the project's
    error-handling policy, initialization failure of the whole image is
    reported clearly rather than silently continuing (CLAUDE.md section 24).
    """


@dataclass(frozen=True)
class VolatilityPluginResult:
    """A constructed plugin together with the context it was built against."""

    context: "ContextInterface"
    plugin: "PluginInterface"


class VolatilityRunner:
    """Constructs Volatility 3 plugins against a single memory image.

    Deliberately OS-agnostic and Go-agnostic: it exposes one operation,
    :meth:`construct_plugin`, parameterized by the plugin class the caller
    wants. Each call builds a *fresh* Volatility ``Context`` so that a
    failed attempt (e.g. trying a Windows plugin against a Linux image)
    never leaves partially-stacked layers or stale config behind for a
    subsequent attempt.
    """

    def __init__(self, image_path: Path) -> None:
        self._image_path = image_path
        _ensure_plugins_imported()

    def construct_plugin(self, plugin_class: "Type[PluginInterface]") -> VolatilityPluginResult:
        """Build a fresh context and construct ``plugin_class`` against it.

        Raises:
            VolatilityInitializationError: if the plugin's requirements
                cannot be satisfied for this image, or Volatility raises any
                other error while attempting to do so.
        """
        from volatility3.framework import automagic, contexts
        from volatility3.framework import exceptions as vol_exceptions
        from volatility3.framework import plugins as vol_plugins
        from volatility3.framework.configuration import requirements

        context = contexts.Context()

        try:
            single_location = requirements.URIRequirement.location_from_file(str(self._image_path))
        except Exception as exc:  # Volatility does not document a narrower type here.
            raise VolatilityInitializationError(
                f"Could not resolve evidence file location for Volatility: {exc}"
            ) from exc

        context.config["automagic.LayerStacker.single_location"] = single_location

        plugin_label = f"{plugin_class.__module__}.{plugin_class.__name__}"
        logger.debug("Attempting to construct %s against %s", plugin_label, self._image_path)

        try:
            available_automagics = automagic.available(context)
            chosen_automagics = automagic.choose_automagic(available_automagics, plugin_class)
            constructed = vol_plugins.construct_plugin(
                context,
                chosen_automagics,
                plugin_class,
                "plugins",
                progress_callback=None,
                open_method=None,
            )
        except vol_exceptions.UnsatisfiedException as exc:
            raise VolatilityInitializationError(
                f"{plugin_label} requirements not satisfied for this image "
                f"(unsatisfied: {sorted(exc.unsatisfied)}). This usually means the "
                f"image is not this OS/architecture, or is unsupported/corrupted."
            ) from exc
        except vol_exceptions.VolatilityException as exc:
            raise VolatilityInitializationError(
                f"Volatility could not process this image with {plugin_label}: {exc}"
            ) from exc

        logger.debug("Successfully constructed %s", plugin_label)
        return VolatilityPluginResult(context=context, plugin=constructed)
