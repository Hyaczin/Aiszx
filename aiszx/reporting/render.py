"""Render the report model as Markdown, HTML or JSON.

Target-controlled text (banners, titles, headers, paths) is untrusted:

* **HTML** uses Jinja2 autoescaping. Only evidence links are emitted as markup, built from
  relative workspace paths (percent-encoded); URLs reported by the target are shown as text and
  never become links.
* **Markdown** escapes every interpolated value (``finalize``) so it cannot add formatting, links,
  table cells or raw HTML. Values meant as code go through the ``code`` filter, which picks a
  backtick fence longer than any backtick run in the value.

Evidence paths in the model are relative to the target directory; ``link_base`` is the relative path
from the output directory to the target directory, so links work wherever the report is written.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any
from urllib.parse import quote

from aiszx.core.errors import AiszxError

TEMPLATE_DIR = Path(__file__).resolve().parent / "templates"
SEV_LABEL = {"critical": "CRITICAL", "high": "HIGH", "medium": "MEDIUM", "low": "LOW", "info": "INFO"}
CLS_LABEL = {"confirmed_observation": "Confirmed observation", "potential_vulnerability": "Potential vulnerability",
             "unverified_hypothesis": "Unverified hypothesis", "requires_manual_validation": "Requires manual validation",
             "false_positive": "False positive (analyst)"}
# `_` between two alphanumerics can never start or end emphasis (CommonMark), so run IDs and module
# names stay readable; every other formatting character is escaped.
_MD_SPECIAL = re.compile(r"([\\`*\[\]<>|~]|(?<![A-Za-z0-9])_|_(?![A-Za-z0-9]))")
# Block markers only matter at the start of a value and only when followed by whitespace
# ("# x", "- x", "1. x"), or as a thematic break ("---"); IPs and versions such as 10.1.2.3 are left alone.
_MD_LEADING = re.compile(r"^(\s*)(?:([#+-]|\d+[.)])(?=\s|$)|([-=]{3,}\s*$))")
_MD_ENTITY = re.compile(r"&(?=#?\w+;)")


class MissingDependency(AiszxError):
    exit_code = 2


class Raw(str):
    """Already-formatted Markdown: not escaped again."""


def _jinja():
    try:
        import jinja2
    except ImportError:
        raise MissingDependency(
            "Jinja2 is required for reports but is not installed in the project environment. "
            "Re-run `bash install.sh` (it installs requirements.txt into .venv only; nothing system-wide).") from None
    return jinja2


def text_of(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, (dict, list)):
        return json.dumps(value, ensure_ascii=False, sort_keys=True, default=str)
    return str(value)


def clip(value: Any, width: int = 200) -> str:
    s = text_of(value)
    return s if len(s) <= width else s[: max(1, width - 1)] + "…"


def oneline(value: Any) -> str:
    return " ".join(text_of(value).split())


def md_escape(value: Any) -> str:
    if isinstance(value, Raw):
        return value
    s = oneline(value)
    s = _MD_ENTITY.sub("&amp;", s)
    s = _MD_SPECIAL.sub(r"\\\1", s)
    return _MD_LEADING.sub(lambda m: m.group(1) + "\\" + (m.group(2) or m.group(3)), s)


def md_code(value: Any) -> Raw:
    s = oneline(value)
    if not s:
        return Raw("")
    longest = max((len(m) for m in re.findall(r"`+", s)), default=0)
    fence = "`" * (longest + 1)
    pad = " " if s.startswith("`") or s.endswith("`") else ""
    return Raw(f"{fence}{pad}{s}{pad}{fence}")


def md_block(value: Any) -> Raw:
    """Fenced code block for multi-line tool output."""
    s = text_of(value).replace("\r", "").strip("\n").rstrip()
    longest = max((len(m) for m in re.findall(r"`{3,}", s)), default=2)
    fence = "`" * (longest + 1)
    return Raw(f"{fence}text\n{s}\n{fence}")


def short(path: str) -> str:
    """Link label for an evidence path: its last two segments (``raw/ferox.json``)."""
    return "/".join((path or "").split("/")[-2:])


def href(link_base: str, path: str) -> str | None:
    if not path or path.startswith(("/", "\\")) or ":" in path.split("/")[0] or ".." in path.split("/"):
        return None
    return (link_base.rstrip("/") + "/" if link_base else "") + quote(path, safe="/")


def _env(fmt: str, link_base: str, max_rows: int, max_value: int):
    j = _jinja()
    if fmt == "html":
        from markupsafe import Markup  # installed with Jinja2

        env = j.Environment(loader=j.FileSystemLoader(TEMPLATE_DIR), autoescape=True, trim_blocks=True,
                            lstrip_blocks=True, undefined=j.StrictUndefined)

        def link(path: str, text: str | None = None):
            h = href(link_base, path or "")
            label = text if text is not None else path
            if h is None:
                return label  # plain text; autoescaped by the template
            return Markup('<a href="{}">{}</a>').format(h, label)
    else:
        env = j.Environment(loader=j.FileSystemLoader(TEMPLATE_DIR), autoescape=False, trim_blocks=True,
                            lstrip_blocks=True, keep_trailing_newline=True, undefined=j.StrictUndefined,
                            finalize=md_escape)

        def link(path: str, text: str | None = None) -> Raw:
            h = href(link_base, path or "")
            label = md_escape(text if text is not None else path)
            return Raw(f"[{label}]({h})") if h else Raw(label)

        env.filters["code"] = md_code
        env.filters["block"] = md_block
        env.filters["esc"] = lambda v: Raw(md_escape(v))
        env.filters["raw"] = lambda v: Raw(str(v))  # macro output is already formatted; do not escape twice
    env.filters["link"] = link
    env.filters["href"] = lambda path: href(link_base, path or "") or ""
    env.filters["clip"] = lambda v, n=max_value: clip(v, n)
    env.filters["oneline"] = oneline
    env.filters["short"] = short
    env.filters["text"] = text_of
    env.filters["sev"] = lambda s: SEV_LABEL.get(s or "", s or "")
    env.filters["cls"] = lambda c: CLS_LABEL.get(c or "", c or "")
    env.globals.update(max_rows=max_rows, max_value=max_value, link_base=link_base)
    return env


def render(model: dict[str, Any], fmt: str, *, link_base: str = "", max_rows: int = 300, max_value: int = 400) -> str:
    if fmt == "json":
        return json.dumps(model, indent=2, ensure_ascii=False, default=str) + "\n"
    template = {"markdown": "report.md.j2", "html": "report.html.j2"}[fmt]
    env = _env(fmt, link_base, max_rows, max_value)
    sections = {k: model[k] for k in model if k != "meta"}
    return env.get_template(template).render(meta=model["meta"], **sections)
