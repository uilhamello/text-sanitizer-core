"""Optional person-name detection with spaCy. Needs spaCy (extra "ner") and the model of each region.

Only person entities are masked. Location entities are ignored on purpose: the Portuguese models
tag technical words as places ("Connection", "p95"); street addresses are left to regional regexes.
"""
from __future__ import annotations

import re

PERSON_LABELS = {"PER", "PERSON"}

# The models read technical text as names ("Docker", "Lock wait timeout exceeded", "Db::add").
# A span is dropped when it cannot be a name: digits or code symbols, or a word from this list
# (names never contain these words). Lower case alone is not enough: people type "joão almeida".
# No "<" or ">": a span may hold an earlier mask ("<PERSON> Pereira") and must still be masked.
_NOT_NAME_CHARS = re.compile(r"[\d/:\[\]()={}_@#$%*\\|]")
_TECH_WORDS = frozenset((
    "authorization", "header", "headers", "kubernetes", "k8s", "pub", "sub", "docker", "db", "lock", "wait",
    "timeout", "exceeded", "error", "erro", "sqlstate", "connection", "http", "https", "git", "checkout",
    "cloud", "deploy", "build", "commit", "merge", "pod", "image", "container", "cluster", "query", "select",
    "null", "exception", "warning", "debug", "server", "endpoint", "token", "cache", "bucket", "queue",
))


def is_name(span: str) -> bool:
    if _NOT_NAME_CHARS.search(span):
        return False
    return not any(w in _TECH_WORDS for w in re.findall(r"[^\W\d_]+", span.lower()))


def load(model: str):
    import spacy  # imported here: the base package has no dependencies

    nlp = spacy.load(model)
    nlp.select_pipes(enable=[p for p in ("tok2vec", "ner") if p in nlp.pipe_names])
    return nlp


def mask_persons(nlp, text: str) -> tuple[str, int]:
    spans = [(e.start_char, e.end_char) for e in nlp(text).ents if e.label_ in PERSON_LABELS
             and is_name(text[e.start_char:e.end_char])]
    for start, end in reversed(spans):  # right to left keeps the earlier offsets valid
        text = text[:start] + "<PERSON>" + text[end:]
    return text, len(spans)
