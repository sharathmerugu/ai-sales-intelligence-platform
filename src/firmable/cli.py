"""`firmable` command line.

    firmable register PATH --snapshot 2026-11-07
    firmable run --workers 4
    firmable status
    firmable retry FILE_ID          # failed chunks get a fresh attempt budget
    firmable replay FILE_ID         # reprocess every chunk (normalizer change)
    firmable seal SNAPSHOT
    firmable evidence OBSERVATION_ID
    firmable build-services SNAPSHOT [--memory-limit 6GB]
    firmable build-phase3 SNAPSHOT [--steps signals attribution accounts serving]
    firmable publish-public SNAPSHOT [--out PATH]   # sanitized serving DB for deployment
    firmable serve [SNAPSHOT] [--port 8000]
    firmable review-set SNAPSHOT [--out CSV]        # stratified account-review set (docs/evaluation.md)
    firmable review-metrics CSV [--source manual|suggested]
    firmable compare-rankings SNAPSHOT [--legacy DIR] [--out FILE]
    firmable inspect-accounts SNAPSHOT [--account ID ...] [--segment S] [--top 40] [--n 8]
    firmable holdout-set SNAPSHOT [--seed N] [--out CSV] [--attribution-version N] [--overwrite]
    firmable holdout-metrics CSV [--labels BLIND_CSV]   # scoring-v3 holdout (docs/evaluation.md)
    firmable agent-brief SNAPSHOT ACCOUNT_ID [--use-case U] [--question Q] [--provider mock|anthropic]
    firmable agent-eval SNAPSHOT [--provider mock|anthropic] [--max-cost USD] [--out DIR]   # docs/agentic-briefs.md
    firmable agent-pregenerate SNAPSHOT [--provider openai_compat] [--per-lens 10] [--answers 3]  # briefs, once
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

import orjson

from .ingest.pipeline import DEFAULT_BATCH_ROWS, DEFAULT_CHUNK_BYTES, Pipeline


def _print(obj: object) -> None:
    sys.stdout.write(orjson.dumps(obj, option=orjson.OPT_INDENT_2 | orjson.OPT_NON_STR_KEYS, default=str).decode() + "\n")


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="firmable")
    ap.add_argument("--workdir", default=os.environ.get("FIRMABLE_WORKDIR", "~/firmable-work"))
    ap.add_argument("--chunk-bytes", type=int, default=DEFAULT_CHUNK_BYTES)
    ap.add_argument("--batch-rows", type=int, default=DEFAULT_BATCH_ROWS)
    sub = ap.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("register", help="hash a source file and plan its chunks")
    p.add_argument("path")
    p.add_argument("--snapshot", help="snapshot id (default: today's UTC date)")

    p = sub.add_parser("run", help="process pending and failed chunks")
    p.add_argument("--workers", type=int, default=2)
    p.add_argument("--max-attempts", type=int, default=3)
    p.add_argument("--file-id", action="append")

    sub.add_parser("status", help="files, chunks, accounting and snapshots")
    for name in ("retry", "replay"):
        sub.add_parser(name).add_argument("file_id")
    sub.add_parser("seal").add_argument("snapshot")
    sub.add_parser("evidence").add_argument("observation_id")
    p = sub.add_parser("build-services", help="observation_flags + services for a snapshot")
    p.add_argument("snapshot")
    p.add_argument("--memory-limit", default="6GB")

    p = sub.add_parser("build-phase3", help="signals, attribution, accounts and serving DB for a sealed snapshot")
    p.add_argument("snapshot")
    p.add_argument("--steps", nargs="+", default=None, help="subset of: signals attribution accounts serving")
    p.add_argument("--memory-limit", default="4GB")
    p.add_argument("--threads", type=int, default=4)

    p = sub.add_parser("publish-public", help="sanitized copy of the serving DB for deployment")
    p.add_argument("snapshot")
    p.add_argument("--out", type=Path, default=None, help="default <workdir>/serving/SNAPSHOT.public.duckdb")

    p = sub.add_parser("review-set", help="stratified account-review CSV: baseline vs enriched ranking")
    p.add_argument("snapshot")
    p.add_argument("--out", type=Path, default=None, help="default <workdir>/eval/SNAPSHOT-review.csv")
    p.add_argument("--seed", type=int, default=20261110)
    p.add_argument("--baseline", type=Path, default=None,
                   help="baseline accounts dir (default: scoring v1 over attribution v2, built at commit 55d86b9)")
    p.add_argument("--overwrite", action="store_true", help="replace an existing CSV (drops its manual labels)")
    p = sub.add_parser("review-metrics", help="metrics from a labeled review CSV")
    p.add_argument("csv", type=Path)
    p.add_argument("--source", choices=("manual", "suggested"), default="manual")

    p = sub.add_parser("compare-rankings", help="offline comparison: legacy scoring v2 vs candidate scoring v3")
    p.add_argument("snapshot")
    p.add_argument("--legacy", type=Path, default=None, help="legacy accounts dir (default: scoring v2, same attribution)")
    p.add_argument("--candidate", type=Path, default=None, help="candidate accounts dir (default: current scoring and attribution)")
    p.add_argument("--out", type=Path, default=None, help="default <workdir>/eval/SNAPSHOT-ranking-compare.json")

    p = sub.add_parser("inspect-accounts", help="re-read source records behind ranked accounts (ownership check)")
    p.add_argument("snapshot")
    p.add_argument("--account", action="append", default=None, help="account id (repeatable); default: top N")
    p.add_argument("--segment", default="enterprise", choices=("enterprise", "network_provider"))
    p.add_argument("--top", type=int, default=40)
    p.add_argument("--n", type=int, default=8, help="records sampled per account")
    p.add_argument("--out", type=Path, default=None, help="default <workdir>/eval/SNAPSHOT-inspect-SEGMENT.{md,json}")

    p = sub.add_parser("holdout-set", help="scoring-v3 evaluation holdout CSV, development cases excluded")
    p.add_argument("snapshot")
    p.add_argument("--out", type=Path, default=None,
                   help="default <workdir>/eval/SNAPSHOT-holdout-v<SCORING_VERSION>[-attrN].csv (refused inside Git)")
    p.add_argument("--seed", type=int, default=None, help="default holdout.HOLDOUT_SEED (20261112)")
    p.add_argument("--attribution-version", type=int, default=None,
                   help="sample the scoring-v3 build over this attribution version (default: current)")
    p.add_argument("--overwrite", action="store_true", help="replace an existing CSV (drops its manual labels)")
    p.add_argument("--no-blind", action="store_true", help="skip the blind CSV (no system_* columns)")
    p = sub.add_parser("holdout-metrics", help="metrics from manual labels on a holdout CSV")
    p.add_argument("csv", type=Path)
    p.add_argument("--labels", type=Path, default=None, help="labeled blind CSV; labels are joined by case_id")

    for name, help_ in (("agent-brief", "run the interpretation agent on one account (synchronous)"),
                        ("agent-eval", "evaluate agent briefs against the deterministic briefs"),
                        ("agent-pregenerate", "generate briefs once for a cohort and store them for serving")):
        p = sub.add_parser(name, help=help_)
        p.add_argument("snapshot")
        if name == "agent-brief":
            p.add_argument("account_id")
            p.add_argument("--use-case", default=None)
            p.add_argument("--question", default=None, help="ask a follow-up instead of building a brief")
            p.add_argument("--signal", default=None, help="focus finding for --question")
            p.add_argument("--trace", action="store_true")
        elif name == "agent-pregenerate":
            p.add_argument("--per-lens", type=int, default=10, help="top research candidates per lens")
            p.add_argument("--verify", type=int, default=2, help="ownership-unresolved accounts per lens")
            p.add_argument("--answers", type=int, default=3, help="accounts per lens whose follow-ups are answered")
            p.add_argument("--dry-run", action="store_true", help="print the cohort only")
            p.add_argument("--max-requests", type=int, default=None,
                           help="model requests for this whole run (free tiers cap requests per day)")
        else:
            p.add_argument("--max-cost", type=float, default=None, help="stop starting runs past this USD total")
            p.add_argument("--scope", default=None, help="run scope (use shared:pregenerated to reuse stored runs)")
            p.add_argument("--out", type=Path, default=None, help="default <workdir>/eval/SNAPSHOT-agent-<provider>-<time>")
        p.add_argument("--provider", choices=["mock", "anthropic", "openai_compat", "none"], default=None,
                       help="default $FIRMABLE_LLM_PROVIDER or mock")
        p.add_argument("--db", type=Path, default=None, help="serving DB (default: the public DB, else the internal one)")
        p.add_argument("--app-db", default=None, help="SQLite run store (default <workdir>/app/agent-runs.sqlite)")

    p = sub.add_parser("serve", help="run the ranked-account API and page")
    p.add_argument("snapshot", nargs="?", help="serve <workdir>/serving/SNAPSHOT.duckdb (default: $FIRMABLE_SERVING_DB)")
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", type=int, default=8000)

    args = ap.parse_args(argv)
    pipe = Pipeline(args.workdir, chunk_bytes=args.chunk_bytes, batch_rows=args.batch_rows)

    if args.cmd == "register":
        _print(pipe.register(args.path, args.snapshot).__dict__)
    elif args.cmd == "run":
        summary = pipe.run(workers=args.workers, max_attempts=args.max_attempts, file_ids=args.file_id)
        _print(summary.__dict__)
        return 1 if summary.failed_chunks else 0
    elif args.cmd == "status":
        _print(pipe.status())
    elif args.cmd == "retry":
        _print({"reset_chunks": pipe.retry(args.file_id)})
    elif args.cmd == "replay":
        _print({"reset_chunks": pipe.replay(args.file_id)})
    elif args.cmd == "seal":
        pipe.seal(args.snapshot)
        _print({"sealed": args.snapshot})
    elif args.cmd == "evidence":
        raw, meta = pipe.evidence(args.observation_id)
        _print({**meta, "record": orjson.loads(raw)})
    elif args.cmd == "build-services":
        from .transform.services import build_services

        _print(build_services(pipe, args.snapshot, memory_limit=args.memory_limit))
    elif args.cmd == "build-phase3":
        from .phase3 import STEPS, build_phase3

        _print(build_phase3(pipe, args.snapshot, steps=tuple(args.steps or STEPS),
                            memory_limit=args.memory_limit, threads=args.threads))
    elif args.cmd == "publish-public":
        from .api.publish import publish_public_db
        from .phase3 import serving_path

        src = serving_path(pipe, args.snapshot)
        _print(publish_public_db(src, args.out or src.with_name(f"{args.snapshot}.public.duckdb")))
    elif args.cmd == "review-set":
        from .accounts.rollup import accounts_dir
        from .attribution.asn import load_openasn
        from .attribution.build import attribution_dir
        from .evaluation.review import build_review_set
        from .signals import signal_hits_path
        from .transform.services import services_path

        enriched = accounts_dir(pipe, args.snapshot)
        # baseline = the ranking before network classification: scoring v1 over attribution v2
        baseline = args.baseline or (pipe.lake / "accounts" / "scoring=v1" / "attribution=v2"
                                     / enriched.parent.name / enriched.name)
        _print(build_review_set(baseline, enriched, attribution_dir(pipe, args.snapshot),
                                signal_hits_path(pipe, args.snapshot), services_path(pipe, args.snapshot),
                                load_openasn(), args.out or pipe.workdir / "eval" / f"{args.snapshot}-review.csv",
                                seed=args.seed, overwrite=args.overwrite))
    elif args.cmd == "review-metrics":
        from .evaluation.review import read_review, review_metrics

        _print(review_metrics(read_review(args.csv), source=args.source))
    elif args.cmd == "compare-rankings":
        from .accounts.rollup import accounts_dir
        from .evaluation.ranking_compare import compare_rankings

        cand = args.candidate or accounts_dir(pipe, args.snapshot)
        legacy = args.legacy or (pipe.lake / "accounts" / "scoring=v2" / cand.parent.parent.name
                                 / cand.parent.name / cand.name)
        if not (legacy / "accounts.parquet").exists():
            # Account ids change across attribution versions, so legacy and candidate must share one.
            raise SystemExit(f"no legacy scoring-v2 tables at {legacy}; pass --legacy and a --candidate built on "
                             "the same attribution version (the recorded comparison uses attribution v4)")
        ev = pipe.workdir / "eval"
        report, detail = compare_rankings(legacy, cand, review_csv=ev / f"{args.snapshot}-review.csv",
                                          inspect_json=ev / f"{args.snapshot}-inspect-enterprise.json")
        out = args.out or ev / f"{args.snapshot}-ranking-compare.json"
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps(report, indent=2, sort_keys=True))
        out.with_name(out.stem + "-detail.json").write_text(json.dumps(detail, indent=2, default=str))
        _print(report)
    elif args.cmd == "inspect-accounts":
        from collections import Counter

        from .accounts.rollup import accounts_dir
        from .evaluation.inspect import inspect_ranked, to_json, to_markdown

        reports = inspect_ranked(pipe, accounts_dir(pipe, args.snapshot), segment=args.segment, top=args.top,
                                 n=args.n, account_ids=args.account)
        out = args.out or pipe.workdir / "eval" / f"{args.snapshot}-inspect-{args.segment}"
        out.parent.mkdir(parents=True, exist_ok=True)
        out.with_suffix(".md").write_text(to_markdown(reports))
        out.with_suffix(".json").write_text(to_json(reports))
        _print({"accounts": len(reports), "records": sum(r["sampled"] for r in reports),
                "verdicts": dict(Counter(r["verdict"] for r in reports)),
                "markdown": str(out.with_suffix(".md")), "json": str(out.with_suffix(".json"))})
    elif args.cmd == "holdout-set":
        from .accounts.eligibility import ELIGIBILITY_VERSION
        from .accounts.rollup import accounts_dir
        from .accounts.scoring import LEGACY_SCORING_VERSION, SCORING_VERSION
        from .attribution.asn import load_openasn
        from .attribution.build import attribution_dir
        from .attribution.names import ATTRIBUTION_VERSION
        from .evaluation.holdout import HOLDOUT_SEED, build_holdout, discover_dev_inputs, with_attribution_version
        from .ingest.normalize import NORMALIZER_VERSION
        from .transform.services import services_path

        att_v = args.attribution_version or ATTRIBUTION_VERSION
        acc, att = accounts_dir(pipe, args.snapshot), attribution_dir(pipe, args.snapshot)
        if args.attribution_version:
            acc, att = with_attribution_version(acc, att_v), with_attribution_version(att, att_v)
        ev = pipe.workdir / "eval"
        dev = discover_dev_inputs(pipe.lake, ev, args.snapshot, Path(__file__).resolve().parents[2] / "docs",
                                  SCORING_VERSION, LEGACY_SCORING_VERSION)
        suffix = f"-attr{att_v}" if args.attribution_version else ""
        try:
            _print(build_holdout(acc, att, services_path(pipe, args.snapshot), load_openasn(), dev,
                                 args.out or ev / f"{args.snapshot}-holdout-v{SCORING_VERSION}{suffix}.csv",
                                 args.snapshot, seed=HOLDOUT_SEED if args.seed is None else args.seed,
                                 overwrite=args.overwrite, blind=not args.no_blind,
                                 versions={"scoring_version": SCORING_VERSION,
                                           "eligibility_version": ELIGIBILITY_VERSION,
                                           "attribution_version": att_v, "normalizer_version": NORMALIZER_VERSION}))
        except (FileExistsError, FileNotFoundError, ValueError) as e:
            raise SystemExit(f"holdout-set: {e}") from None
    elif args.cmd == "holdout-metrics":
        from .evaluation.holdout import holdout_metrics, read_holdout

        try:
            rows = read_holdout(args.csv, labels=args.labels)
        except (FileNotFoundError, ValueError) as e:
            raise SystemExit(f"holdout-metrics: {e}") from None
        _print(holdout_metrics(rows))
    elif args.cmd in ("agent-brief", "agent-eval", "agent-pregenerate"):
        return _agent_command(args, pipe)
    elif args.cmd == "serve":
        import uvicorn

        from .api.app import create_app
        from .phase3 import serving_path

        db = serving_path(pipe, args.snapshot) if args.snapshot else None
        # Persist runs and briefs next to the other working files unless told otherwise.
        os.environ.setdefault("FIRMABLE_APP_DB", str(pipe.workdir / "app" / "agent-runs.sqlite"))
        uvicorn.run(create_app(db), host=args.host, port=args.port)
    return 0


def _agent_command(args: argparse.Namespace, pipe: Pipeline) -> int:
    import time as _time

    from .agent.config import AgentConfig
    from .agent.runs import RunStore
    from .agent.service import BriefService
    from .api.store import Store
    from .phase3 import serving_path
    from .semantic import SemanticLayer

    db = args.db
    if db is None:
        public = pipe.workdir / "serving" / f"{args.snapshot}.public.duckdb"
        db = public if public.exists() else serving_path(pipe, args.snapshot)
    env = dict(os.environ)
    env["FIRMABLE_LLM_PROVIDER"] = args.provider or env.get("FIRMABLE_LLM_PROVIDER") or "mock"
    config = AgentConfig.from_env(env)
    app_db = args.app_db or str(pipe.workdir / "app" / (f"{args.snapshot}.briefs.sqlite"
                                                        if args.cmd == "agent-pregenerate" else "agent-runs.sqlite"))
    if args.cmd == "agent-pregenerate":
        # Generation is one-off and slow on a local CPU: wide per-run budgets, no hourly / daily throttles.
        config = config.with_(max_seconds=float(env.get("FIRMABLE_AGENT_MAX_SECONDS") or 1800),
                              runs_per_hour=10**9, retry_cooldown_s=0.0, workers=1)
    semantic = SemanticLayer(Store(db))
    service = BriefService(semantic, config, RunStore(app_db), owner=False)
    try:
        if args.cmd == "agent-brief":
            resp = service.run_now(kind="ask" if args.question else "brief", account_id=args.account_id,
                                   use_case=args.use_case, scope="cli:local", question=args.question,
                                   signal_id=args.signal)
            run = resp.pop("run", None) or {}
            out = {"state": resp["state"], "cache": resp.get("cache"), "run_id": resp.get("run_id"),
                   "disposition": run.get("disposition"), "metrics": run.get("metrics"), "output": resp["output"]}
            if args.trace:
                out["trace"] = run.get("trace")
                out["issues"] = run.get("issues")
            _print(out)
            return 0
        if args.cmd == "agent-pregenerate":
            from .agent.pregenerate import cohort, pregenerate

            items = cohort(service, args.per_lens, args.verify)
            if args.dry_run:
                _print({"app_db": app_db, "items": items})
                return 0
            summary = pregenerate(service, items, args.answers, Path(app_db).with_suffix(".progress.jsonl"),
                                  max_requests=args.max_requests)
            _print({"app_db": app_db, **summary})
            return 0
        from .evaluation.agent_eval import run_eval

        stamp = _time.strftime("%Y%m%dT%H%M%S")
        out_dir = args.out or pipe.workdir / "eval" / f"{args.snapshot}-agent-{config.provider}-{stamp}"
        summary = run_eval(semantic, service, Path(out_dir), max_cost_usd=args.max_cost, scope=args.scope)
        _print({"out": str(out_dir), **summary})
        return 0
    except KeyError as e:
        raise SystemExit(f"{args.cmd}: account not found: {e}") from None
    finally:
        service.close()


if __name__ == "__main__":
    raise SystemExit(main())
