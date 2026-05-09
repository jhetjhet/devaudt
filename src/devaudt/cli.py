"""
devintel-deterministic — entry point

Usage examples
--------------
# Analyse a remote repository (clones into a temp sandbox automatically)
    python main.py --url https://github.com/jhetjhet/austin-portfolio

# Analyse a local checkout
    python main.py --path /path/to/repo

# Write the result to a file instead of stdout
    python main.py --url <url> --output result.json
"""

import argparse
import json
import sys

from devaudt.analyzer import analyze_local, analyze_url
from devaudt.analyzer.risk import RiskScoringEngine
from devaudt.analyzer.correlation import EvidenceCorrelationEngine
from devaudt.analyzer.context import ContextCompressor


def _parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Deterministic static code analyzer (Python · TypeScript · JavaScript)"
    )
    group = p.add_mutually_exclusive_group(required=True)
    group.add_argument("--url",  metavar="URL",  help="Remote Git repository URL to clone and analyze")
    group.add_argument("--path", metavar="PATH", help="Local repository path to analyze")
    p.add_argument(
        "--output", metavar="FILE",
        help="Write JSON result to FILE instead of stdout",
    )
    p.add_argument(
        "--indent", type=int, default=2,
        help="JSON indentation level (default: 2, use 0 for compact)",
    )
    p.add_argument(
        "--risk", action="store_true",
        help="Run the Risk Scoring Engine and append a 'risk_report' key to the output",
    )
    p.add_argument(
        "--risk-only", action="store_true",
        help="Output only the risk report (implies --risk)",
    )
    p.add_argument(
        "--correlate", action="store_true",
        help="Run the Evidence Correlation Engine after risk scoring and append a 'correlation_report' key",
    )
    p.add_argument(
        "--correlate-only", action="store_true",
        help="Output only the correlation report (implies --risk and --correlate)",
    )
    p.add_argument(
        "--compress", action="store_true",
        help="Run the Context Compressor and append a 'context_packet' key (implies --correlate)",
    )
    p.add_argument(
        "--compress-only", action="store_true",
        help="Output only the context packet as JSON (implies --correlate)",
    )
    p.add_argument(
        "--compress-top-n", type=int, default=3, metavar="N",
        help="Number of hotspot clusters to include in the context packet (default: 3)",
    )
    p.add_argument(
        "--compress-token-budget", type=int, default=8000, metavar="TOKENS",
        help="Approximate token budget for the context packet (default: 8000)",
    )
    return p.parse_args()


def main() -> None:
    args = _parse_args()

    print("[devintel] Starting analysis…", file=sys.stderr)

    if args.url:
        print(f"[devintel] Cloning {args.url} …", file=sys.stderr)
        result = analyze_url(args.url)
    else:
        print(f"[devintel] Analyzing local path: {args.path}", file=sys.stderr)
        result = analyze_local(args.path)

    print("[devintel] Analysis complete.", file=sys.stderr)

    indent = args.indent if args.indent > 0 else None

    run_risk = (
        args.risk or args.risk_only
        or args.correlate or args.correlate_only
        or args.compress or args.compress_only
    )
    if run_risk:
        print("[devintel] Running Risk Scoring Engine\u2026", file=sys.stderr)
        risk_report = RiskScoringEngine().score(result)
        print(
            f"[devintel] Risk scoring done \u2014 {risk_report.total_entities} entities profiled.",
            file=sys.stderr,
        )

    run_correlate = (
        args.correlate or args.correlate_only
        or args.compress or args.compress_only
    )
    if run_correlate:
        print("[devintel] Running Evidence Correlation Engine\u2026", file=sys.stderr)
        correlation_report = EvidenceCorrelationEngine().correlate(risk_report)
        print(
            f"[devintel] Correlation done \u2014 {correlation_report.total_clusters} clusters found.",
            file=sys.stderr,
        )

    run_compress = args.compress or args.compress_only
    if run_compress:
        print("[devintel] Running Context Compressor\u2026", file=sys.stderr)
        context_packet = ContextCompressor().compress(
            result,
            risk_report,
            correlation_report,
            top_n=args.compress_top_n,
            token_budget=args.compress_token_budget,
        )
        print(
            f"[devintel] Compression done \u2014 "
            f"{len(context_packet.included_clusters)} cluster(s) included, "
            f"~{context_packet.token_estimate} tokens.",
            file=sys.stderr,
        )

    if args.compress_only:
        payload = json.dumps(context_packet.to_dict(), indent=indent, ensure_ascii=False)
    elif args.correlate_only:
        payload = json.dumps(correlation_report.to_dict(), indent=indent, ensure_ascii=False)
    elif args.risk_only:
        payload = json.dumps(risk_report.to_dict(), indent=indent, ensure_ascii=False)
    elif run_compress:
        data = result.to_dict()
        data["risk_report"] = risk_report.to_dict()
        data["correlation_report"] = correlation_report.to_dict()
        data["context_packet"] = context_packet.to_dict()
        payload = json.dumps(data, indent=indent, ensure_ascii=False)
    elif run_correlate:
        data = result.to_dict()
        data["risk_report"] = risk_report.to_dict()
        data["correlation_report"] = correlation_report.to_dict()
        payload = json.dumps(data, indent=indent, ensure_ascii=False)
    elif run_risk:
        data = result.to_dict()
        data["risk_report"] = risk_report.to_dict()
        payload = json.dumps(data, indent=indent, ensure_ascii=False)
    else:
        payload = json.dumps(result.to_dict(), indent=indent, ensure_ascii=False)

    if args.output:
        with open(args.output, "w", encoding="utf-8") as fh:
            fh.write(payload)
        print(f"[devintel] Result written to {args.output}", file=sys.stderr)
    else:
        print(payload)


if __name__ == "__main__":
    main()
