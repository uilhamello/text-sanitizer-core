"""Regional packages as plugins, loaded by name from the "text_sanitizers" entry point group.

A region (text-sanitizer-br, a future text-sanitizer-eu...) registers a Region object:

    [project.entry-points.text_sanitizers]
    br = "text_sanitizer_br:REGION"

build(["br", "eu"]) returns ONE Sanitizer with the core rules plus every region's masks, so the
text is scanned once. Fail secure: a region that is missing or fails to load blocks every call.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from importlib.metadata import entry_points

from .sanitizer import Report, Sanitizer

GROUP = "text_sanitizers"


@dataclass(frozen=True)
class Region:
    name: str
    masks: list = field(default_factory=list)  # [(name, regex, replacement), ...] like the core masks
    ner_model: str | None = None               # spaCy model for person names in this region's language


class _Blocked:
    """Stands in for a Sanitizer that could not be built: blocks every call with the reasons."""

    def __init__(self, reasons):
        self.reasons = list(reasons)

    def sanitize(self, text) -> tuple[str, Report]:
        return "", Report(blocked=list(self.reasons))


def load_regions(names) -> tuple[list[Region], list[str]]:
    available = {ep.name: ep for ep in entry_points(group=GROUP)}
    regions, errors = [], []
    for name in names:
        if name not in available:
            errors.append(f"region_missing:{name}")
            continue
        try:
            region = available[name].load()
        except Exception as e:
            errors.append(f"region_failed:{name}:{type(e).__name__}")
            continue
        if not isinstance(region, Region):
            errors.append(f"region_invalid:{name}")
            continue
        regions.append(region)
    return regions, errors


def build(names, *, ner: bool = False, **options):
    """Sanitizer for the given regions (core only when names is empty). Never raises on a bad region."""
    regions, errors = load_regions(names)
    models = list(dict.fromkeys(r.ner_model for r in regions if r.ner_model)) if ner else []
    if ner and not errors and not models:
        errors.append("ner_unavailable:no_region_model")
    if errors:
        return _Blocked(errors)
    return Sanitizer(region_masks=[m for r in regions for m in r.masks], ner_models=models, **options)
