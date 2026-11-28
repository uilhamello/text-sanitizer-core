"""text-sanitizer-core — engine and country-independent rules for masking PII and secrets in text."""
__version__ = "0.3.0"

from .plugins import GROUP, Region, build, load_regions  # noqa: E402
from .sanitizer import (CORE_MASKS_AFTER, CORE_MASKS_BEFORE, DEFAULT_BLOCKS, Report, Sanitizer,  # noqa: E402
                        id_after_words, login_after_words, sanitize)

__all__ = ["Sanitizer", "Report", "sanitize", "Region", "build", "load_regions", "GROUP",
           "CORE_MASKS_BEFORE", "CORE_MASKS_AFTER", "DEFAULT_BLOCKS", "id_after_words", "login_after_words", "__version__"]
