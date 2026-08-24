#!/usr/bin/env python3
"""Generate (and re-check) Policy.bestFit()'s table from Microsoft's own file.

WHY THIS EXISTS. The table in Policy.java has been hand-curated twice and been
INCOMPLETE both times -- first thirteen separator entries, then a hundred and
five. Each subset was defensible when it was written and each left a live
denylist bypass: `/account/l<U+FF0F>gout` the first time,
`/account/<U+0142>ogout` the second. A third hand-drawn line would have been
wrong the same way, so the table is no longer drawn by hand. It is emitted from
the vendor file, verbatim, by this script.

THE SOURCE.

    https://unicode.org/Public/MAPPINGS/VENDORS/MICSFT/WindowsBestFit/bestfit1252.txt
    sha256 72ea23c939c5b26fae7aded0207b327e2f3902d7d3c168d7087f5cfc38ee76a9
    (fetched 2026-08-23; CODEPAGE 1252, MBTABLE 256, WCTABLE 698 entries)

The WCTABLE half is what WideCharToMultiByte consults going wide -> ANSI. An
entry `0x0142  0x6c` says a Windows program that hands U+0142 to an "A" API
gets the byte 0x6c, which is `l`. That substitution is the whole attack: the
path that reaches the filesystem is not the path that was routed.

THE FILTER, and it is the only judgement in here: an entry is taken when its
SOURCE is non-ASCII and its TARGET is 0x20..0x7E. 392 of the 698 entries
qualify. Everything else either starts in ASCII (128 entries, identities) or
lands outside printable ASCII (178, mostly 1252's own high half) and cannot
change what a path SAYS to a matcher whose patterns are ASCII.

0x20 is inside the filter on purpose, and it is 8 entries -- the quad/em spaces
and U+3000 IDEOGRAPHIC SPACE. A space is not decorative here: Windows trims a
trailing space from a name, so `/a/<U+3000>/b/leaf` reads as `/a/b/leaf` and an
exclusion on `/a/b/*` has to see it.

THE SUPPLEMENT. Six code points are folded that this file does NOT map to
printable ASCII. They were in the hand-drawn table and they stay, because a
best-fit reading of a PATH only ever denies more -- but the reason the old
comment gave for them ("best fits in other code pages' tables") is FALSE, and
that is worth writing down rather than repeating. Checked against the WCTABLEs
of bestfit932, 936, 949, 950, 874, 1250-1258 and 10000 as well as 1252: none of
these six best-fits to printable ASCII in ANY of them. U+2024 is in 1252 and
maps to 0xB7 MIDDLE DOT, not to `.`; we fold it to `.` anyway, which is
stricter than the table and is a homoglyph judgement rather than a vendor fact.
They are kept as homoglyphs of path syntax, labelled as such:

    U+29F8 BIG SOLIDUS                  -> /
    U+FE68 SMALL REVERSE SOLIDUS        -> backslash
    U+FE52 SMALL FULL STOP              -> .
    U+FF61 HALFWIDTH IDEOGRAPHIC STOP   -> .
    U+2024 ONE DOT LEADER               -> .   (1252 says MIDDLE DOT)
    U+FE54 SMALL SEMICOLON              -> ;

KNOWN LIMIT, stated rather than discovered later: this is 1252's table, which
is the ANSI code page of a Windows host installed for a Western locale. A
Japanese host is 932 and a Chinese one 936, and their tables are different and
much larger -- the union over the fifteen tables named above is 530 code points
against this file's 392. Folding that union would map large parts of CJK onto
ASCII and would refuse any CJK scope outright, so it is not done. If an
engagement is against a CJK Windows estate, this fold is a subset of what that
target will do.

USAGE.

    python3 extension/tools/bestfit_table.py --emit        # the case lines
    python3 extension/tools/bestfit_table.py --check       # compare to Policy.java

--check re-derives the table and byte-compares the emitted lines against the
block in Policy.java between the two GENERATED markers, so a hand edit to the
table is a non-zero exit rather than a comment nobody re-read. It reads a local
copy of the vendor file if one is given with --source, and otherwise fetches
it; there is no network at RUNTIME anywhere in this project, and this script is
not runtime -- it is a build-time author's tool that nothing imports.
"""
from __future__ import annotations

import argparse
import hashlib
import re
import sys
import urllib.request
from pathlib import Path

URL = ("https://unicode.org/Public/MAPPINGS/VENDORS/MICSFT/WindowsBestFit/"
       "bestfit1252.txt")
SHA256 = "72ea23c939c5b26fae7aded0207b327e2f3902d7d3c168d7087f5cfc38ee76a9"

BEGIN = "            // ---- GENERATED from bestfit1252.txt; see bestfit_table.py ----"
END = "            // ---- END GENERATED ----"

# Homoglyphs of path syntax that no Microsoft table best-fits to ASCII. See the
# module docstring; the third field is why each one is here.
SUPPLEMENT = [
    (0x29F8, "/",  "BIG SOLIDUS"),
    (0xFE68, "\\", "SMALL REVERSE SOLIDUS"),
    (0xFE52, ".",  "SMALL FULL STOP"),
    (0xFF61, ".",  "HALFWIDTH IDEOGRAPHIC FULL STOP"),
    (0x2024, ".",  "ONE DOT LEADER (bestfit1252 says MIDDLE DOT)"),
    (0xFE54, ";",  "SMALL SEMICOLON"),
]


def fetch(source: Path | None) -> str:
    if source is not None:
        raw = Path(source).read_bytes()
    else:
        with urllib.request.urlopen(URL, timeout=60) as fh:  # noqa: S310
            raw = fh.read()
    got = hashlib.sha256(raw).hexdigest()
    if got != SHA256:
        raise SystemExit(
            f"bestfit1252.txt sha256 is {got}, expected {SHA256}. The vendor "
            f"file changed; re-read it before regenerating the table."
        )
    return raw.decode("latin-1")


ENTRY = re.compile(r"^(0x[0-9a-fA-F]+)\s+(0x[0-9a-fA-F]+)\s*(?:;(.*))?$")


def wctable(text: str) -> list[tuple[int, int, str]]:
    lines = text.splitlines()
    starts = [i for i, l in enumerate(lines) if l.startswith("WCTABLE")]
    if len(starts) != 1:
        raise SystemExit(f"expected one WCTABLE section, found {len(starts)}")
    declared = int(lines[starts[0]].split()[1])
    out = []
    for line in lines[starts[0] + 1:]:
        if line.startswith("ENDCODEPAGE"):
            break
        line = line.strip()
        if not line:
            continue
        m = ENTRY.match(line)
        if not m:
            raise SystemExit(f"unparsed WCTABLE line: {line!r}")
        out.append((int(m.group(1), 16), int(m.group(2), 16),
                    (m.group(3) or "").strip()))
    if len(out) != declared:
        raise SystemExit(f"WCTABLE declares {declared} entries, parsed {len(out)}")
    return out


def table(text: str) -> list[tuple[int, str, str]]:
    """(source, target character, comment), sorted by source."""
    rows = {}
    for src, tgt, name in wctable(text):
        if src > 0x7F and 0x20 <= tgt <= 0x7E:
            rows[src] = (chr(tgt), name.upper())
    for src, tgt, why in SUPPLEMENT:
        if src in rows:
            raise SystemExit(f"supplement U+{src:04X} is already in the table")
        rows[src] = (tgt, why + "  [not in any Microsoft table]")
    return [(src, rows[src][0], rows[src][1]) for src in sorted(rows)]


def java_literal(c: str) -> str:
    if c == "'":
        return r"'\''"
    if c == "\\":
        return r"'\\'"
    return f"'{c}'"


def emit(rows: list[tuple[int, str, str]]) -> str:
    lines = [BEGIN]
    for src, tgt, name in rows:
        lines.append(f"            case 0x{src:04x}: return {java_literal(tgt)};"
                     f"  // {name}")
    lines.append(END)
    return "\n".join(lines)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--source", type=Path, default=None,
                    help="a local copy of bestfit1252.txt (else it is fetched)")
    ap.add_argument("--emit", action="store_true")
    ap.add_argument("--check", action="store_true")
    ap.add_argument("--digest", action="store_true",
                    help="the sha256 PolicyTest pins, over the table itself")
    ap.add_argument("--policy", type=Path,
                    default=Path(__file__).resolve().parents[1]
                    / "src" / "hx" / "policy" / "Policy.java")
    args = ap.parse_args()

    rows = table(fetch(args.source))
    block = emit(rows)

    if args.emit:
        print(block)
    if args.digest:
        # One `%04x:%02x` line per entry, ascending. PolicyTest recomputes this
        # over the mapping it DISCOVERS from the compiled class and compares,
        # so a target changed in place -- which leaves the entry count and
        # every property check alone -- is still a red.
        blob = "".join(f"{src:04x}:{ord(tgt):02x}\n" for src, tgt, _ in rows)
        print(hashlib.sha256(blob.encode()).hexdigest())
    if args.check:
        text = args.policy.read_text(encoding="utf-8")
        start = text.find(BEGIN)
        stop = text.find(END)
        if start < 0 or stop < 0:
            print(f"{args.policy}: generated markers not found", file=sys.stderr)
            return 1
        got = text[start:stop + len(END)]
        if got != block:
            print(f"{args.policy}: the table is not what this script emits.",
                  file=sys.stderr)
            want_lines, got_lines = block.splitlines(), got.splitlines()
            for i, (a, b) in enumerate(zip(want_lines, got_lines), 1):
                if a != b:
                    print(f"  line {i}\n    want {a!r}\n    got  {b!r}",
                          file=sys.stderr)
                    break
            else:
                print(f"  want {len(want_lines)} lines, got {len(got_lines)}",
                      file=sys.stderr)
            return 1
        print(f"{args.policy}: table matches ({len(rows)} entries)")
    if not args.emit and not args.check and not args.digest:
        print(f"{len(rows)} entries; pass --emit or --check", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
