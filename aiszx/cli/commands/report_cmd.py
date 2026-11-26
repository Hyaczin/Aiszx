"""``report TARGET`` (Markdown/HTML/JSON) and ``compare TARGET`` (run-to-run changes)."""

from __future__ import annotations

import argparse
import json
from typing import Any

from aiszx.app import AppContext
from aiszx.cli.commands import engagement_slug
from aiszx.cli.output import emit_json
from aiszx.core.errors import NotFoundError, ValidationError
from aiszx.reporting.settings import FORMATS

FORMAT_ALIASES = {"md": "markdown", "markdown": "markdown", "html": "html", "json": "json"}
SEV = {"critical": "CRIT", "high": "HIGH", "medium": "MED", "low": "LOW", "info": "INFO"}


def register(sub: argparse._SubParsersAction, common: argparse.ArgumentParser) -> None:
    r = sub.add_parser("report", parents=[common], help="write Markdown, HTML and JSON reports for a target",
                       description="Builds a report from everything known about the target (latest result of every "
                                   "module across runs, current findings) and stores it as a new run under "
                                   "runs/<run>/reports/. Secrets are redacted. With reporting.write_consolidated "
                                   "(default) the same report is also written to <target>/consolidated/.")
    r.add_argument("target")
    r.add_argument("--format", "-f", dest="formats", action="append", metavar="FMT",
                   help=f"md, html or json; repeat or comma-separate (default: reporting.formats = {', '.join(FORMATS)})")
    r.add_argument("--json", action="store_true", help="print the file locations as JSON")
    r.set_defaults(handler=cmd_report)

    c = sub.add_parser("compare", parents=[common], help="what changed between runs of a target",
                       description="Compares ports, services, web data and findings. --latest (default) compares the "
                                   "two most recent runs holding each kind of data; --from/--to pins two runs. "
                                   "The result is also saved under <target>/history/.")
    c.add_argument("target")
    c.add_argument("--latest", action="store_true", help="compare the two most recent runs per category (default)")
    c.add_argument("--from", dest="from_run", metavar="RUN_ID", help="older run")
    c.add_argument("--to", dest="to_run", metavar="RUN_ID", help="newer run")
    c.add_argument("--json", action="store_true")
    c.set_defaults(handler=cmd_compare)


def parse_formats(values: list[str] | None) -> tuple[str, ...] | None:
    if not values:
        return None
    out = []
    for v in values:
        for part in v.split(","):
            part = part.strip().lower()
            if part not in FORMAT_ALIASES:
                raise ValidationError(f"unknown report format {part!r} (use md, html or json)")
            out.append(FORMAT_ALIASES[part])
    return tuple(dict.fromkeys(out))


def cmd_report(ctx: AppContext, args: argparse.Namespace) -> int:
    from aiszx.reporting.service import Reporter

    slug = engagement_slug(ctx, args)
    res = Reporter(ctx).run(slug, args.target, parse_formats(args.formats))
    if args.json:
        emit_json({"run_id": res.run_id, "files": {k: str(v) for k, v in res.files.items()},
                   "consolidated": {k: str(v) for k, v in res.consolidated.items()},
                   "redactions": res.model["meta"]["redactions"]})
        return 0
    m = res.model
    print(f"Report {res.run_id} for {m['meta']['target']} (engagement {m['meta']['engagement']})")
    for line in m["summary"]["lines"]:
        print(f"  {line}")
    if m["summary"]["stale_warning"]:
        print(f"  note: {m['summary']['stale_warning']}")
    print(f"  redacted values: {m['meta']['redactions']}")
    print("Files:")
    for fmt, path in res.files.items():
        print(f"  {fmt:<8} {path}")
    if res.consolidated:
        print(f"Latest view (overwritten on each report): {next(iter(res.consolidated.values())).parent}")
    if "html" in res.files:
        print(f"Open in a browser: xdg-open {res.files['html']}")
    return 0


# --- compare ------------------------------------------------------------------

def _run_label(c: dict[str, Any]) -> str:
    f, t = c["from"], c["to"]
    return f"{f['run_id']} ({f['command']}, {f['profile']}) → {t['run_id']} ({t['command']}, {t['profile']})"


def _svc(d: dict[str, Any]) -> str:
    return " ".join(x for x in (d.get("name"), d.get("product"), d.get("version")) if x) or "-"


def print_compare(result: dict[str, Any]) -> None:
    cats = result["categories"]
    print(f"Changes for {result['target']} ({'two most recent runs per category' if result['mode'] == 'latest' else 'pinned runs'})")
    for name, title in (("ports", "Ports"), ("services", "Services"), ("web", "Web"), ("findings", "Findings")):
        c = cats[name]
        print(f"\n{title}: " + (_run_label(c) if c["compared"] else f"not compared ({c['reason']})"))
        if not c["compared"]:
            continue
        lines: list[str] = []
        if name == "ports":
            lines += [f"  + {p['protocol']}/{p['port']} {p['state']}" for p in c["opened"]]
            lines += [f"  - {p['protocol']}/{p['port']} (was {p['state']})" for p in c["closed"]]
            lines += [f"  ~ {p['protocol']}/{p['port']} {p['before']} → {p['after']}" for p in c["state_changed"]]
        elif name == "services":
            lines += [f"  + {s['service']} {_svc(s)}" for s in c["new"]]
            lines += [f"  - {s['service']} {_svc(s)}" for s in c["removed"]]
            for s in c["changed"]:
                diffs = ", ".join(f"{k} {v['before'] or '-'} → {v['after'] or '-'}" for k, v in s["changes"].items())
                lines.append(f"  ~ {s['service']} {diffs}")
        elif name == "web":
            lines += [f"  + endpoint {u}" for u in c["endpoints_new"]]
            lines += [f"  - endpoint {u}" for u in c["endpoints_removed"]]
            for e in c["endpoints_changed"]:
                diffs = ", ".join(f"{k} {v['before']} → {v['after']}" for k, v in e["changes"].items())
                lines.append(f"  ~ endpoint {e['url']} {diffs}")
            lines += [f"  + tech {t['name']} {t['version'] or ''} ({t['endpoint']})" for t in c.get("technologies_new", [])]
            lines += [f"  - tech {t['name']} {t['version'] or ''} ({t['endpoint']})" for t in c.get("technologies_removed", [])]
            lines += [f"  ~ tech {t['name']} {t['before'] or '-'} → {t['after'] or '-'} ({t['endpoint']})"
                      for t in c.get("technologies_changed", [])]
            lines += [f"  + resource {u}" for u in c.get("resources_new", [])]
            lines += [f"  - resource {u} (no longer found)" for u in c.get("resources_removed", [])]
        else:
            lines += [f"  + {f['id']} [{SEV.get(f['severity'], f['severity'])}] {f['title']}" for f in c["new"]]
            lines += [f"  - {f['id']} {f['title']} (no longer reproduced; kept)" for f in c["not_reproduced"]]
            for f in c["changed"]:
                diffs = ", ".join(f"{k} {v['before']} → {v['after']}" for k, v in f["changes"].items())
                lines.append(f"  ~ {f['id']} {f['title']}: {diffs}")
        print("\n".join(lines) if lines else "  no changes")
        for note in c.get("notes", []):
            print(f"  note: {note}")
    s = result["summary"]
    print("\nSummary: " + ("; ".join(s["lines"]) if s["lines"] else
                           "no changes" if s["no_changes"] else "nothing could be compared yet"))


def cmd_compare(ctx: AppContext, args: argparse.Namespace) -> int:
    from aiszx.reporting.service import compare_and_store

    if args.latest and (args.from_run or args.to_run):
        raise ValidationError("--latest cannot be combined with --from/--to")
    try:
        result, path = compare_and_store(ctx, engagement_slug(ctx, args), args.target, args.from_run, args.to_run)
    except ValueError as exc:
        raise ValidationError(str(exc)) from None
    except LookupError as exc:
        raise NotFoundError(str(exc)) from None
    if args.json:
        emit_json(json.loads(json.dumps(result, default=str)) | {"saved_to": str(path)})
        return 0
    print_compare(result)
    print(f"Saved: {path}")
    return 0
