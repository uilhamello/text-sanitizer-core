"""text-sanitizer-core — engine and country-independent rules for masking PII and secrets in text."""
__version__ = "0.1.0"

from .plugins import GROUP, Region, build, load_regions  # noqa: E402
from .sanitizer import CORE_MASKS_AFTER, CORE_MASKS_BEFORE, DEFAULT_BLOCKS, Report, Sanitizer, sanitize  # noqa: E402

__all__ = ["Sanitizer", "Report", "sanitize", "Region", "build", "load_regions", "GROUP",
           "CORE_MASKS_BEFORE", "CORE_MASKS_AFTER", "DEFAULT_BLOCKS", "__version__"]
