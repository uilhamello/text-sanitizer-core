"""Mask PII and secrets; block when something risky survives masking.

Fail secure: when in doubt, block. Only the text returned here may leave the machine.

The core holds the rules that do not depend on a country (secrets, e-mail, card, IP...). Regional
packages (text-sanitizer-br, ...) add their own masks, which run between CORE_MASKS_BEFORE and
CORE_MASKS_AFTER: after secrets and e-mail, before the generic number and IP rules that would
otherwise take pieces of a document number.
"""
from __future__ import annotations

import math
import re
from dataclasses import dataclass, field

from . import ner as _ner

_SECRET_WORDS = (r"pass(?:word|wd)?|senha|pwd|pw|token|secret|segredo|api[_\s-]?key|apikey|auth(?:orization)?|cookie"
                 r"|sess(?:ion)?(?:_?id)?|sid|credentials?|credencia(?:l|is)|chave|t?otp")
# As a key, the secret word may close a longer name: APP_SID, PHPSESSID, APP_TOKEN, db.password.
# It may also be followed by a short, specific suffix: SECRET_KEY, AUTH_KEY, SECRET_ACCESS_KEY, secret_value.
# Never a generic one: token_ttl, password_min_length and session_timeout are config, not secrets.
_SECRET_KEY = (r"[A-Za-z0-9_.-]*?(?:" + _SECRET_WORDS + r")"
               r"(?:[_.-]?(?:hash|digest|salt|(?:access[_.-]?)?key|value))?")
# Characters of a loose password token (no path, URL, placeholder or quote characters).
_PW = r"[^\s/:<>\"'(),;=]"
# Words that tie the keyword to its value in free text: "a senha é x", "the password is x".
_LINK_WORDS = r"é|eh|era|foi|fica|ficou|is|was"
# Values that say "no secret here": masking them only hides the diagnosis.
_FILE_EXT = (r"ya?ml|json|xml|js|ts|py|php|sql|html?|css|md|txt|log|ini|conf|env|lock|csv|sh|jar|plugin|gradle"
             r"|toml|cfg|go|rb|java|kt|vue|tsx|jsx|zip|gz|tar|pdf|png|jpe?g")
_EMPTY = r"(?!(?:null|none|nil|ok|true|false|undefined)\b)"

# Tokens with a well-known prefix: masked even when they would not trip the entropy check.
_KNOWN_TOKENS = (r"xox[abposr]-[A-Za-z0-9-]{10,}|gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}"
                 r"|sk-(?:ant-)?[A-Za-z0-9_-]{20,}|[sr]k_(?:live|test)_[A-Za-z0-9]{16,}|AIza[0-9A-Za-z_-]{16,}")


def _luhn(digits: str) -> bool:
    total = 0
    for i, d in enumerate(reversed(digits)):
        n = int(d) * (2 if i % 2 else 1)
        total += n - 9 if n > 9 else n
    return total % 10 == 0


def _vin(m: re.Match) -> str:
    """Vehicle identification number (17 chars, no I/O/Q): masked only when it mixes letters and digits."""
    t = m.group(0)
    return "<VIN>" if re.search(r"\d", t) and re.search(r"[A-Za-z]", t) else t


def _ipv6(m: re.Match) -> str:
    """Compressed IPv6 ("2001:db8::1", "::1"): needs a digit, so C++/PHP scopes (Db::add) survive."""
    return "<IP>" if re.search(r"\d", m.group(0)) else m.group(0)


# A number or hash right after these words, or a number before a unit, is a metric, size, build or commit.
_NUM_KEY = re.compile(r"(?i)(?:epoch|timestamp|rows[_ ]?(?:examined|sent|affected)|content-length|bytes|size|build"
                      r"|release|vers[aã]o|version)\s*[:=#-]?\s*$")
_NUM_UNIT = re.compile(r"(?i)\s*(?:ms|µs|us|ns|s|seg(?:undos?)?|min(?:utos?)?|bytes?|[kmg]b|centavos|rows|linhas"
                       r"|registros)\b")
_HEX_KEY = re.compile(r"(?i)(?:commit|sha\d*|checksum|etag|rev(?:ision)?)\s*[:=]?\s*$")
_HEX_DIGITS = frozenset("0123456789abcdefABCDEF")
_IP_VERSION = re.compile(r"(?i)(?:\b(?:chrome|chromium|firefox|safari|edge?|opr|version|applewebkit|mozilla|gecko|crios"
                         r"|curl|python|node|php|java|go|okhttp|dalvik)/|\bv|vers[aã]o\s*|version\s*)$")


def _long_number(m: re.Match) -> str:
    s, i, j = m.string, m.start(), m.end()
    while i and s[i - 1] in _HEX_DIGITS:
        i -= 1
    while j < len(s) and s[j] in _HEX_DIGITS:
        j += 1
    if j - i >= 32:  # digits inside a hash that _long_hex kept (commit, checksum)
        return m.group(0)
    before, after = m.string[max(0, m.start() - 30):m.start()], m.string[m.end():m.end() + 12]
    if _NUM_KEY.search(before):
        return m.group(0)
    # A unit alone is weak evidence: 11+ digits may be a document (CPF, RENAVAM, CNH) with a stray "bytes" after it.
    return m.group(0) if len(m.group(0)) <= 10 and _NUM_UNIT.match(after) else "<N>"


def _long_hex(m: re.Match) -> str:
    """Hash after "commit" or "sha256" is a commit or checksum. After "hash" or "md5" it may be a password hash."""
    return m.group(0) if _HEX_KEY.search(m.string[max(0, m.start() - 20):m.start()]) else "<HEX>"


def _ipv4(m: re.Match) -> str:
    """Four numbers with dots after a product name or "versão" ("Chrome/120.0.0.0", "versão 1.2.3.4") are a version."""
    return m.group(0) if _IP_VERSION.search(m.string[max(0, m.start() - 12):m.start()]) else "<IP>"


def _secret_word(m: re.Match) -> str:
    """Free-text secret. A bare number after filler words is a metric ("token expira em 3600"), not a secret;
    right after the keyword it is one ("totp 482913")."""
    if m.group("f") and m.group("v").isdigit():
        return m.group(0)
    return f"{m.group('k')}{m.group('f')} <SECRET>"


def id_after_words(words: str) -> tuple:
    """Short number right after a word that names an entity ("user 4521", "pedido nº 98765", "loja #312")."""
    return ("id_word", r"(?i)\b(?P<w>(?:" + words + r")s?)(?P<sep>\s*(?:n[º°o]\.?|#|:|=|/)?\s*)#?\d{1,5}\b",
            r"\g<w>\g<sep><ID>")


def login_after_words(words: str) -> tuple:
    """Login right after a word that names it ("login=fsilva", "usuario: fulano.silva").
    The value must start with a letter (a number is an ID, handled elsewhere)."""
    return ("login_word", r"(?i)\b(?P<w>(?:" + words + r"))(?P<sep>\s*[:=]\s*[\"']?)" + _EMPTY
            + r"(?!(?:inv[aá]lid[oa]|invalid|vazio|empty|desconhecid[oa]|unknown|n[aã]o|not)\b)"
            r"[A-Za-z][\w.@-]*", r"\g<w>\g<sep><USER>")


def _card(m: re.Match) -> str:
    """Payment card (13-19 digits, spaces or dashes allowed): masked only when the Luhn check passes."""
    digits = re.sub(r"\D", "", m.group(0))
    return "<CARD>" if 13 <= len(digits) <= 19 and _luhn(digits) else m.group(0)


# Order matters: specific patterns before generic ones (e.g. JWT before long hex).
# The replacement may be a callable (see _card), as accepted by re.sub.
CORE_MASKS_BEFORE: list[tuple] = [
    ("private_key", r"(?s)-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----", "<PRIVATE_KEY>"),
    ("jwt", r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b", "<JWT>"),
    # Whole Authorization header, whatever the scheme (Basic, Token, Bearer, custom).
    ("auth_header", r"(?im)\b(?P<k>(?:proxy-)?authorization\s*:\s*)[^\n'\"]+", r"\g<k><SECRET>"),
    # Credentials on a command line: curl -u user:pass, mysql -pPASS (attached, as the client requires).
    ("cli_user", r"(?P<k>(?:^|\s)(?:-u|--user)\s+)[^\s:'\"]+:[^\s'\"]+", r"\g<k><USERINFO>"),
    ("cli_mysql_p", r"(?i)(?P<k>\b(?:mysql|mysqldump|mysqladmin|mariadb)\b[^\n]*?\s-p)(?!\s)[^\s'\"]+", r"\g<k><SECRET>"),
    # Token in a URL path: /reset/token/<value>, /verify/<value>.
    ("path_token", r"(?i)(?P<k>/(?:[\w-]*token|reset|verify|confirm|activate|invite|magic[\w-]*)/)(?=[A-Za-z0-9_-]*\d)"
                   r"[A-Za-z0-9_-]{8,}", r"\g<k><TOKEN>"),
    ("bearer", r"(?i)\bbearer\s+[A-Za-z0-9._~+/=-]{8,}", "Bearer <TOKEN>"),
    ("auth_scheme", r"(?i)\b(?P<s>basic|digest|negotiate|ntlm)\s+[A-Za-z0-9+/=._-]{6,}", r"\g<s> <TOKEN>"),
    ("password_hash", r"\$(?:2[abxy]?|argon2(?:id|i|d)|[156])\$[^\s\"']{8,}", "<HASH>"),
    ("known_token", r"\b(?:" + _KNOWN_TOKENS + r")", "<TOKEN>"),
    # Before regional documents and long_number, which would otherwise take pieces of the number.
    ("card", r"(?<![\d.])\d(?:[ -]?\d){12,18}(?![\d.])", _card),
    # Dotted groups of four ("4111.1111.1111.1111"); dots stay out of the rule above for metrics like 51.000.000.
    ("card_dotted", r"(?<![\d.])\d{4}(?:\.\d{4}){2,3}(?:\.\d{1,3})?(?![\d.])", _card),
    ("card_cvv", r"(?i)\b(?P<k>cvv2?|cvc2?|cid)\s*[:=]?\s*\d{3,4}\b", r"\g<k> <CVV>"),
    ("card_expiry", r"(?i)\b(?P<k>exp(?:iry|ires|iration)?|valid(?:ity|ade)?|venc(?:imento)?)\s*[:=]?\s*"
                    r"(?:0[1-9]|1[0-2])\s*/\s*(?:\d{2}|\d{4})\b", r"\g<k> <EXPIRY>"),
    ("vin", r"(?i)\b[A-HJ-NPR-Z0-9]{17}\b", _vin),
    # URL userinfo (scheme://user:pass@host) before anything else sees the "@".
    ("url_userinfo", r"(?i)\b([a-z][a-z0-9+.-]*://)[^\s/?#@]+@", r"\1<USERINFO>@"),
    # Whole cookie header: every pair in it is session state.
    ("cookie_header", r"(?im)\b(?P<k>(?:set-)?cookie\s*:\s*)[^\n]+", r"\g<k><SECRET>"),
    # key=value, key: value, and quoted keys as in JSON ("password": "x").
    ("secret_kv", r"(?i)\b(?P<k>" + _SECRET_KEY + r")\b(?P<sep>[\"']?\s*[=:]\s*)" + _EMPTY + r"(?:\"[^\"]*\"|'[^']*'|[^\s,;&}]+)",
     r"\g<k>\g<sep><SECRET>"),
    # Free text ("a senha é hunter2"): skip up to 3 short words, mask the first token with a digit.
    # Composite key, space, value: "APP_SID abc123def", "APP_TOKEN x9y8z7w6".
    ("secret_key_space", r"(?i)\b(?P<k>[A-Za-z0-9]+[_.-](?:[A-Za-z0-9]+[_.-])*?(?:sid|sessid|session_?id|token|secret|key"
                         r"|pass(?:word|wd)?))\s+[^\s,;&<]{6,}", r"\g<k> <SECRET>"),
    ("secret_word", r"(?i)\b(?P<k>" + _SECRET_KEY + r")\b(?P<f>(?:\s+[^\W\d_]{1,7}){0,3}?)\s+(?=[^\s,;&]*\d)(?P<v>[^\s,;&]{4,})",
     _secret_word),
    # "a senha é passarinhoazul": the link word makes the next token the value, digit or not.
    ("secret_is", r"(?i)\b(?P<k>" + _SECRET_WORDS + r")(?P<f>(?:\s+[^\W\d_]{1,7}){0,3}?)(?P<l>\s+(?:" + _LINK_WORDS
     + r")\s+|\s*[=:]\s*)" + _EMPTY + r"(?:\"[^\"]*\"|'[^']*'|[^\s,;&<]{3,})", r"\g<k>\g<f>\g<l><SECRET>"),
    # Loose password with no keyword: upper, lower, digit and symbol in one 8-64 char token.
    ("password_like", r"(?<![^\s\"'(])(?=" + _PW + r"*[a-z])(?=" + _PW + r"*[A-Z])(?=" + _PW + r"*\d)"
                      r"(?=" + _PW + r"*[!@#$%^&*?~+])" + _PW + r"{8,64}(?![^\s\"',;)])", "<SECRET>"),
    ("url_query", r"(https?://[^\s?#]+)\?[^\s#]*", r"\1?<QUERY>"),
    ("email", r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b", "<EMAIL>"),
    # Written to dodge filters: fulano%40x.com, fulano[at]x.com, fulano (arroba) x (ponto) com.
    ("email_obfuscated", r"(?i)\b[A-Za-z0-9._+%-]+(?:%40|\s*[\[({]\s*(?:at|arroba)\s*[\])}]\s*)[A-Za-z0-9-]+"
                         r"(?:(?:\.|%2e|\s*[\[({]\s*(?:dot|ponto)\s*[\])}]\s*)[A-Za-z0-9-]+)+", "<EMAIL>"),
    # "@" with spaces around it or in full width ("fulano @ example.com", "fulano＠example.com"): known TLD only,
    # so code like "A @ B.T" (matrix product) stays.
    ("email_spaced", r"(?i)\b[A-Za-z0-9._+%-]+(?:\s+@\s*|\s*@\s+|\s*[＠﹫]\s*)[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*"
                     r"\.(?:com|net|org|br|io|gov|edu|co|info|dev|app|pt|es|us|uk)\b", "<EMAIL>"),
    # Spelled out without brackets ("fulano.silva at example dot com"): needs "at" and a known TLD after "dot".
    ("email_spelled", r"(?i)\b[A-Za-z0-9._+-]+\s+(?:at|arroba)\s+[A-Za-z0-9-]+(?:\s+(?:dot|ponto)\s+[A-Za-z0-9-]+)*"
                      r"\s+(?:dot|ponto)\s+(?:com|net|org|br|io|gov|edu|co|info|dev|app|pt|es|us|uk)\b", "<EMAIL>"),
    # No TLD ("fulano.silva@intranet"): local part with a dot or underscore; package tags and digests stay.
    ("email_no_tld", r"(?<![\w@/.-])[A-Za-z][A-Za-z+-]*[._][A-Za-z][A-Za-z0-9._+-]*@(?!(?:latest|next|beta|alpha|canary|rc|stable"
                     r"|sha\d+|v?\d)\b)[A-Za-z][A-Za-z0-9-]*\b(?![.@:/])", "<EMAIL>"),
]

CORE_MASKS_AFTER: list[tuple] = [
    ("uuid", r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b", "<UUID>"),
    # Part of a longer dotted chain ("OID 1.3.6.1.4.1") is not an address.
    ("ipv4", r"(?<!\d\.)\b(?:\d{1,3}\.){3}\d{1,3}\b(?!\.\d)", _ipv4),
    # IP written with dashes inside a hostname ("203-0-113-45.example.net", "ip-10-0-0-5.ec2.internal").
    ("ipv4_dashed", r"(?i)(?:\bip-|\b)(?:\d{1,3}-){3}\d{1,3}(?=\.[a-z])(?!\.(?:" + _FILE_EXT + r"|release)\b)", "<IP>"),
    ("ipv6", r"\b(?:[0-9a-fA-F]{1,4}:){4,7}[0-9a-fA-F]{1,4}\b", "<IP>"),
    ("ipv6_short", r"(?<![\w:])(?:[0-9a-fA-F]{1,4}(?::[0-9a-fA-F]{1,4}){0,6})?::(?:[0-9a-fA-F]{1,4}(?::[0-9a-fA-F]{1,4}){0,6})?(?![\w:])",
     _ipv6),
    ("long_hex", r"\b[0-9a-fA-F]{32,}\b", _long_hex),
    login_after_words(r"user(?:_?name)?|login|author"),
    # @first.last handle; decorators ("@app.route(", "@pytest.mark.x", "@login_required") are left alone.
    ("handle", r"(?<![\w.@])@(?!(?:app|self|pytest|router|bot|client|api|celery|bp|blueprint|dp)\.)"
               r"[a-z][a-z0-9]*\.[a-z0-9]+(?![\w.(/-])", "@<USER>"),
    ("handle_by", r"\b(?P<w>(?i:by|por|author|autor)\s+)[a-z]{2,}[._](?!(?:" + _FILE_EXT + r")\b)[a-z]{2,}\b(?![.(/])",
     r"\g<w><USER>"),
    id_after_words(r"user|customer|client|account|order|store|seller|buyer|ticket"),
    # 6+ digit number without separators: treated as an identifier (raw document, card, account id).
    ("long_number", r"(?<![\d.,])\d{6,}(?![\d.,])", _long_number),
    ("id_kv", r"(?P<k>\b(?i:u?id(?:_[a-z]+)?|[a-z]+_id|cod_[a-z]+)|\b[a-z]+Id)(?P<sep>[\"']?\s*[=:]?\s*)\d+",
     r"\g<k>\g<sep><N>"),
]

# Detectors that BLOCK even after masking (cannot be masked safely).
DEFAULT_BLOCKS: list[tuple[str, str]] = [
    ("aws_key", r"\b(AKIA|ASIA)[A-Z0-9]{16}\b"),
    ("gcp_key", r"(?i)\"?private_key(_id)?\"?\s*:"),
    ("pem_header", r"-----BEGIN [A-Z ]*(PRIVATE KEY|CERTIFICATE)-----"),
    ("residual_at", r"[^\s>]@\S+\.\S"),  # ">@" is a mask placeholder (<USERINFO>@host)
    ("residual_at_encoded", r"(?i)[^\s>]%40\S+\.\S"),
    ("conn_string", r"(?i)\b(mysql|postgres(ql)?|mongodb(\+srv)?|redis|amqp|mssql|jdbc:[a-z]+)://"),
]

_SUSPECT_TOKEN = re.compile(r"[A-Za-z0-9+/_=-]{24,}")


@dataclass
class Report:
    masks: dict[str, int] = field(default_factory=dict)
    blocked: list[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return not self.blocked

    def merge(self, other: "Report", where: str = "") -> None:
        for name, count in other.masks.items():
            self.masks[name] = self.masks.get(name, 0) + count
        self.blocked += [f"{where}:{b}" if where else b for b in other.blocked]


def _entropy(s: str) -> float:
    return -sum(s.count(c) / len(s) * math.log2(s.count(c) / len(s)) for c in set(s))


class Sanitizer:
    """Core rules + regional masks + extra patterns. Defaults cannot be removed.

    ner_models: spaCy models for person names, one per language. If any cannot be loaded, every
    call is blocked: asking for names and silently skipping them would be worse than failing.
    """

    def __init__(self, region_masks=(), extra_masks=(), extra_blocks=(), max_chars: int = 20000,
                 entropy_threshold: float = 4.0, ner_models=()):
        # Secrets and e-mail run BEFORE the name model: it may tag the keyword itself ("Cookie" -> <PERSON>)
        # and the value would then lose its anchor. The caller's rules come right after the secrets, so they win
        # over the generic ones ("TCK-4521" is a ticket, not a plate) without unanchoring a password.
        # Everything else runs after the name model, on the original wording.
        self.pre_masks = [(n, re.compile(p), r) for n, p, r in [*CORE_MASKS_BEFORE, *extra_masks]]
        self.masks = [(n, re.compile(p), r) for n, p, r in [*region_masks, *CORE_MASKS_AFTER]]
        self.blocks = [(n, re.compile(p)) for n, p in [*DEFAULT_BLOCKS, *extra_blocks]]
        self.max_chars = max_chars
        self.entropy_threshold = entropy_threshold
        self._nlps, self._ner_error = [], None
        for model in ner_models:
            try:
                self._nlps.append(_ner.load(model))
            except Exception as e:  # ImportError (no spaCy) or OSError (no model): fail secure, see sanitize
                self._ner_error = f"ner_unavailable:{type(e).__name__}"

    def _high_entropy(self, text: str) -> bool:
        for m in _SUSPECT_TOKEN.finditer(text):
            t = m.group(0)
            classes = sum(bool(re.search(p, t)) for p in (r"[a-z]", r"[A-Z]", r"\d"))
            if classes >= 3 and _entropy(t) >= self.entropy_threshold:
                return True
        return False

    @staticmethod
    def _apply(rules, text: str, report: Report) -> str:
        for name, rx, repl in rules:
            if callable(repl):  # count only the matches the rule really changed (_card, _ipv4 may keep them)
                changed = 0

                def repl_counting(m, f=repl):
                    nonlocal changed
                    out = f(m)
                    changed += out != m.group(0)
                    return out

                text = rx.sub(repl_counting, text)
                n = changed
            else:
                text, n = rx.subn(repl, text)
            if n:
                report.masks[name] = report.masks.get(name, 0) + n
        return text

    def sanitize(self, text) -> tuple[str, Report]:
        report = Report()
        if not isinstance(text, str):
            report.blocked.append("not_text")
            return "", report
        # Size first: the regexes are not linear on adversarial input, so oversized text never reaches them.
        if len(text) > self.max_chars:
            report.blocked.append(f"too_long>{self.max_chars}")
            return "", report
        if self._ner_error:
            report.blocked.append(self._ner_error)
            return "", report
        clean = self._apply(self.pre_masks, text, report)
        for nlp in self._nlps:
            clean, n = _ner.mask_persons(nlp, clean)
            if n:
                report.masks["person"] = report.masks.get("person", 0) + n
        clean = self._apply(self.masks, clean, report)
        report.blocked += [name for name, rx in self.blocks if rx.search(clean)]
        if self._high_entropy(clean):
            report.blocked.append("high_entropy")
        if len(clean) > self.max_chars:
            report.blocked.append(f"too_long>{self.max_chars}")
        return clean, report


_default = Sanitizer()


def sanitize(text) -> tuple[str, Report]:
    """Sanitize with the core rules only (no regional documents)."""
    return _default.sanitize(text)
