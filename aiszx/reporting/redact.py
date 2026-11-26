"""Secret redaction for general-purpose reports.

Everything that goes into a report passes through :class:`Redactor` first, so credentials, session
tokens, keys and hashes seen in tool output never appear in Markdown, HTML or JSON reports. Raw
evidence files are not modified; reports reference them by path and hash.

Two mechanisms:

* **Key-based:** in structured data, values under secret-looking keys (``password``, ``token``,
  ``authorization``, ``community`` ...) are replaced. Cookie headers keep cookie *names* and
  attributes (needed to explain e.g. a missing HttpOnly flag) but lose the values.
* **Pattern-based:** free text is scanned for URL credentials, ``key=value`` secrets, Authorization
  and Cookie headers, private key blocks, LM:NT hashes, JWTs and cloud access keys.

Redaction is deliberately conservative: a false redaction costs a little readability, a missed
secret leaks it. Only the *number* of redactions is reported, never the values.
"""

from __future__ import annotations

import re
from typing import Any, Iterable

MASK = "[REDACTED]"

SECRET_KEY_RE = re.compile(
    r"^(?:.*[\s_.-])?(?:password|passwd|passwords|pwd|passphrase|secret|secrets|client[_-]?secret|token|tokens|"
    r"access[_-]?token|refresh[_-]?token|api[_-]?key|apikey|access[_-]?key|private[_-]?key|authorization|"
    r"proxy-authorization|credential|credentials|community|communities|nthash|lmhash|ntlm[_-]?hash)$",
    re.IGNORECASE)
COOKIE_KEY_RE = re.compile(r"^(?:set-)?cookie2?$", re.IGNORECASE)
COOKIE_ATTRS = {"path", "domain", "expires", "max-age", "samesite", "secure", "httponly", "priority", "partitioned",
                "version", "comment"}
# Publicly documented defaults are not secrets; masking them would also mangle ordinary words
# ("Public files"). Literal masking of configured values skips these and anything shorter than 4.
KNOWN_DEFAULT_LITERALS = {"public", "private"}

_COOKIE_LINE = re.compile(r"(?i)\b((?:set-)?cookie2?\s*:\s*)([^\r\n]*)")
_COOKIE_PAIR = re.compile(r"([^=;,\s]+)\s*=\s*([^;]*)")


def _mask_cookie_value(text: str) -> tuple[str, int]:
    n = 0

    def pair(m: re.Match) -> str:
        nonlocal n
        name, value = m.group(1), m.group(2)
        if name.lower() in COOKIE_ATTRS or not value.strip():
            return m.group(0)
        n += 1
        return f"{name}={MASK}"

    return _COOKIE_PAIR.sub(pair, text), n


DEFAULT_PATTERNS: list[tuple[str, str]] = [
    # PEM private key blocks (any type)
    (r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----.*?-----END [A-Z0-9 ]*PRIVATE KEY-----", MASK),
    # scheme://user:password@host
    (r"(?i)\b([a-z][a-z0-9+.-]*://[^/\s:@]+):([^@\s/]+)@", r"\1:" + MASK + "@"),
    # Authorization: Basic xxx / Bearer xxx
    (r"(?i)\b((?:proxy-)?authorization\s*[:=]\s*(?:basic|bearer|digest|ntlm|negotiate|token)?\s*)[^\s,;]+",
     r"\1" + MASK),
    # password=..., "token": "...", api_key: ...
    (r"(?i)([\"']?\b(?:password|passwd|pwd|passphrase|secret|client[_-]?secret|token|access[_-]?token|"
     r"refresh[_-]?token|api[_-]?key|apikey|access[_-]?key|auth[_-]?key)[\"']?\s*[=:]\s*)"
     r"(\"[^\"]*\"|'[^']*'|[^\s,;&\"'<>]+)", r"\1" + MASK),
    # LM:NT hash pairs (secretsdump/pwdump style)
    (r"\b[0-9a-fA-F]{32}:[0-9a-fA-F]{32}\b", MASK),
    # JSON Web Tokens
    (r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b", MASK),
    # AWS access key IDs
    (r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b", MASK),
]


class Redactor:
    def __init__(self, *, extra_patterns: Iterable[str] = (), extra_secret_keys: Iterable[str] = (),
                 literals: Iterable[str] = ()) -> None:
        self.patterns = [(re.compile(p, re.DOTALL), r) for p, r in DEFAULT_PATTERNS]
        self.patterns += [(re.compile(p), MASK) for p in extra_patterns]
        self.extra_keys = {k.lower() for k in extra_secret_keys}
        lits = sorted({x for x in literals if isinstance(x, str) and len(x) >= 4
                       and x.lower() not in KNOWN_DEFAULT_LITERALS}, key=len, reverse=True)
        self.literal_re = re.compile(r"(?<![\w])(?:" + "|".join(map(re.escape, lits)) + r")(?![\w])") if lits else None
        self.count = 0

    # -- text ---------------------------------------------------------------
    def text(self, s: str) -> str:
        if not s:
            return s

        def cookie_line(m: re.Match) -> str:
            masked, n = _mask_cookie_value(m.group(2))
            self.count += n
            return m.group(1) + masked

        s = _COOKIE_LINE.sub(cookie_line, s)
        for rx, repl in self.patterns:
            s, n = rx.subn(repl, s)
            self.count += n
        if self.literal_re is not None:
            s, n = self.literal_re.subn(MASK, s)
            self.count += n
        return s

    def is_secret_key(self, key: str) -> bool:
        return bool(SECRET_KEY_RE.match(key)) or key.lower() in self.extra_keys

    # -- structured data ----------------------------------------------------
    def value(self, obj: Any, key: str | None = None) -> Any:
        if key is not None and isinstance(key, str):
            if COOKIE_KEY_RE.match(key) and isinstance(obj, str):
                masked, n = _mask_cookie_value(obj)
                self.count += n
                return masked
            if self.is_secret_key(key) and obj not in (None, "", [], {}) and not isinstance(obj, (bool, dict, list)):
                self.count += 1
                return MASK
            if self.is_secret_key(key) and isinstance(obj, list) and obj and all(isinstance(x, str) for x in obj):
                self.count += len(obj)
                return [MASK] * len(obj)
        if isinstance(obj, str):
            return self.text(obj)
        if isinstance(obj, dict):
            return {k: self.value(v, k if isinstance(k, str) else None) for k, v in obj.items()}
        if isinstance(obj, (list, tuple)):
            return [self.value(v, key if COOKIE_KEY_RE.match(key or "") else None) for v in obj]
        return obj
