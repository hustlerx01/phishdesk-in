"""Usage: python -m phishdesk.cli <file.eml|dir> [-o outdir]"""
import argparse, json
from pathlib import Path
from .analyze import analyze_file
from .report import to_markdown


def main(argv=None):
    ap = argparse.ArgumentParser(description="PhishDesk-IN .eml analyser")
    ap.add_argument("target"); ap.add_argument("-o", "--out", default="")
    args = ap.parse_args(argv)
    t = Path(args.target)
    files = sorted(t.glob("*.eml")) if t.is_dir() else [t]
    out = Path(args.out) if args.out else None
    if out:
        out.mkdir(parents=True, exist_ok=True)
    for f in files:
        r = analyze_file(f)
        print(f"{r['verdict']:10s} {r['score']:3d}  {f.name}  {r['subject'][:60]}")
        if out:
            (out / f"{f.stem}.json").write_text(json.dumps(r, indent=2, ensure_ascii=False))
            (out / f"{f.stem}.md").write_text(to_markdown(r))


if __name__ == "__main__":
    main()
