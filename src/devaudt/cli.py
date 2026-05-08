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
    payload = json.dumps(result.to_dict(), indent=indent, ensure_ascii=False)

    if args.output:
        with open(args.output, "w", encoding="utf-8") as fh:
            fh.write(payload)
        print(f"[devintel] Result written to {args.output}", file=sys.stderr)
    else:
        print(payload)


if __name__ == "__main__":
    main()
