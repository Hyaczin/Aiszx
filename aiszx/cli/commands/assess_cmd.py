"""``assess`` (observations → findings) and ``findings list|show|mark``."""

from __future__ import annotations

import argparse
import json

from aiszx.app import AppContext
from aiszx.assessment.engine import Assessor, AssessmentReport
from aiszx.assessment.model import CLASSIFICATIONS, SCALE_HELP, priority
from aiszx.cli.commands import engagement_slug, help_handler
from aiszx.cli.output import emit_json, kv, table
from aiszx.core.audit import record_event
from aiszx.core.errors import NotFoundError
from aiszx.core.timeutil import iso

SEV_TAG = {"critical": "CRIT", "high": "HIGH", "medium": "MED", "low": "LOW", "info": "INFO"}
CLS_TAG = {"confirmed_observation": "confirmed", "potential_vulnerability": "potential",
           "unverified_hypothesis": "hypothesis", "false_positive": "false+", "requires_manual_validation": "validate"}


def register(sub: argparse._SubParsersAction, common: argparse.ArgumentParser) -> None:
    a = sub.add_parser("assess", parents=[common], help="turn collected observations into findings",
                       description="Applies the assessment rules to the latest result of every module across the "
                                   "target's runs, reconciles findings (stable IDs; analyst decisions kept; findings "
                                   "that no longer appear become not_reproduced) and lists what to investigate next.")
    a.add_argument("target")
    a.add_argument("--no-exploitdb", action="store_true", help="skip offline searchsploit version hypotheses")
    a.add_argument("--json", action="store_true")
    a.set_defaults(handler=cmd_assess)

    f = sub.add_parser("findings", help="list, show and annotate findings")
    f.set_defaults(handler=help_handler(f))
    fsub = f.add_subparsers(dest="findings_action", metavar="ACTION")
    ls = fsub.add_parser("list", parents=[common], help="current findings of a target")
    ls.add_argument("target")
    ls.add_argument("--all", action="store_true", help="include not_reproduced and false positives")
    ls.add_argument("--min-severity", choices=("info", "low", "medium", "high", "critical"), default="info")
    ls.add_argument("--json", action="store_true")
    ls.set_defaults(handler=cmd_list)
    sh = fsub.add_parser("show", parents=[common], help="details of one finding")
    sh.add_argument("finding_id", metavar="FINDING")
    sh.set_defaults(handler=cmd_show)
    mk = fsub.add_parser("mark", parents=[common], help="record an analyst decision (kept across re-assessments)")
    mk.add_argument("finding_id", metavar="FINDING")
    mk.add_argument("--as", dest="classification", required=True, choices=(*CLASSIFICATIONS, "clear"),
                    help="analyst classification, or 'clear' to remove it")
    mk.add_argument("--note", help="analyst note (e.g. why it is a false positive)")
    mk.set_defaults(handler=cmd_mark)


def print_report(report: AssessmentReport, target: str, prefix: str) -> None:
    print(f"Assessment {report.run_id} of {target}: {len(report.findings)} finding(s) "
          f"({sum(f.new for f in report.findings)} new, {len(report.not_reproduced)} no longer reproduced)")
    print(f"  based on runs: {', '.join(report.knowledge_runs) or '-'}")
    if report.findings:
        print(table([(f.id, SEV_TAG[f.draft.severity], f.draft.confidence, CLS_TAG[f.classification],
                      ("* " if f.new else "") + f.draft.title[:70], f.draft.service_key or f.draft.location or "")
                     for f in report.findings],
                    ("ID", "SEV", "CONF", "CLASS", "TITLE (* = new)", "WHERE")))
    if report.paths:
        print("\nInvestigate next (manual, within authorised scope):")
        for i, p in enumerate(report.paths[:12], 1):
            print(f"  {i:>2}. [{SEV_TAG[p['severity']]}] {p['step']}  ({p['finding']})")
    for note in report.limitations:
        print(f"note: {note}")
    print(f"\nDetails: {prefix} findings show <ID>   |   dismiss: {prefix} findings mark <ID> --as false_positive --note ...")


def _prefix(ctx: AppContext, slug: str) -> str:
    return "python3 pentest.py" + ("" if slug == ctx.config.default_engagement else f" -e {slug}")


def cmd_assess(ctx: AppContext, args: argparse.Namespace) -> int:
    slug = engagement_slug(ctx, args)
    report = Assessor(ctx).run(slug, args.target, exploitdb_lookup=not args.no_exploitdb)
    if args.json:
        emit_json(json.loads((report.run_dir / "findings" / "findings.json").read_text(encoding="utf-8"))
                  | {"investigation": report.paths})
        return 0
    print_report(report, args.target, _prefix(ctx, slug))
    return 0


def _rows(ctx: AppContext, args: argparse.Namespace):
    eng = ctx.engagements().get(engagement_slug(ctx, args))
    target = ctx.targets().get(eng, args.target)
    return target, ctx.db.query("SELECT * FROM findings WHERE target_id = ?", (target.id,))


def _cls(row) -> str:
    return row["analyst_classification"] or row["classification"]


def cmd_list(ctx: AppContext, args: argparse.Namespace) -> int:
    target, rows = _rows(ctx, args)
    order = ("info", "low", "medium", "high", "critical")
    rows = [r for r in rows if order.index(r["severity"]) >= order.index(args.min_severity)]
    if not args.all:
        rows = [r for r in rows if r["status"] == "open" and _cls(r) != "false_positive"]
    rows.sort(key=lambda r: -priority(r["severity"], r["confidence"], _cls(r)))
    if args.json:
        emit_json([dict(r) | {"effective_classification": _cls(r)} for r in rows])
        return 0
    if not rows:
        print(f"No findings for {target.canonical}. Run `assess {target.canonical}` after recon/enumeration.")
        return 0
    print(table([(r["id"], SEV_TAG[r["severity"]], r["confidence"], CLS_TAG[_cls(r)], r["status"],
                  r["title"][:70], r["service_key"] or r["location"] or "") for r in rows],
                ("ID", "SEV", "CONF", "CLASS", "STATUS", "TITLE", "WHERE")))
    return 0


def _get(ctx: AppContext, fid: str):
    row = ctx.db.query_one("SELECT f.*, t.canonical_id FROM findings f JOIN targets t ON t.id = f.target_id "
                           "WHERE f.id = ?", (fid.strip(),))
    if row is None:
        raise NotFoundError(f"finding {fid} not found (see `findings list TARGET`)")
    return row


def cmd_show(ctx: AppContext, args: argparse.Namespace) -> int:
    r = _get(ctx, args.finding_id)
    print(f"{r['id']}: {r['title']}")
    print(kv([
        ("target", r["canonical_id"]), ("where", r["service_key"] or r["location"]), ("rule", r["rule_id"]),
        ("severity", f"{r['severity']}  ({SCALE_HELP['severity']})"),
        ("confidence", f"{r['confidence']}  ({SCALE_HELP['confidence']})"),
        ("classification", f"{_cls(r)}  ({SCALE_HELP[_cls(r)]})"
         + (f"  [analyst override; rule said {r['classification']}]" if r["analyst_classification"] else "")),
        ("status", r["status"]), ("first seen", r["first_seen_at"]), ("last seen", r["last_seen_at"]),
        ("analyst note", r["analyst_notes"]),
    ]))
    print(f"\nDescription: {r['description']}")
    if r["impact"]:
        print(f"Impact:      {r['impact']}")
    if r["recommendation"]:
        print(f"Remediation: {r['recommendation']}")
    steps = json.loads(r["next_steps_json"])
    if steps:
        print("Next steps:")
        for s in steps:
            print(f"  - {s}")
    evidence = json.loads(r["evidence_json"])
    if evidence:
        print("Evidence:")
        for e in evidence:
            print(f"  - run {e['run_id']} {e['module']} [{e['unit']}] observation {e['observation']}")
            for path in e["files"]:
                print(f"      {path}")
    return 0


def cmd_mark(ctx: AppContext, args: argparse.Namespace) -> int:
    r = _get(ctx, args.finding_id)
    value = None if args.classification == "clear" else args.classification
    with ctx.db.transaction():
        ctx.db.execute("UPDATE findings SET analyst_classification = ?, analyst_notes = COALESCE(?, analyst_notes),"
                       " analyst_updated_at = ? WHERE id = ?", (value, args.note, iso(), r["id"]))
        record_event(ctx.db, "finding.mark", actor=ctx.actor, target_id=r["target_id"], finding=r["id"],
                     classification=value, note=args.note)
    print(f"{r['id']} marked as {value or 'rule classification (' + r['classification'] + ')'}")
    return 0
