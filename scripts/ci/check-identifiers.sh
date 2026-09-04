#!/usr/bin/env bash
# Fail if a tracked file names real infrastructure.
#
# This gate exists because it was needed. A CGNAT address of the machine hx was
# written on, and its Tailscale IPv6 counterpart, sat in tests/test_burp_fixture.py
# as "examples of non-loopback addresses" through 447 of 609 commits. Scrubbing the
# working tree does not scrub a clone; the history had to be rewritten before this
# repository could be published. A rule that caught something once must not be able
# to stop catching it.
#
# The rules below are deliberately narrow. A blanket "no public IPv4" rule would
# fire on every Chromium version string in the browser tests (150.0.7871.186 parses
# as a dotted quad), and a gate that cries wolf is a gate somebody turns off.
set -uo pipefail

fail=0
report() { # <description> <matches>
    printf '\n%s\n' "$1"
    printf '%s\n' "$2" | sed 's/^/    /'
    fail=1
}

files=$(git ls-files)

# 1. Tailscale ULA. Tailscale allocates every tailnet address inside one fixed /48
#    whose first group is fd7a, so an address matching it belongs to a real tailnet.
#    There is no legitimate example use. Written without the literal prefix on
#    purpose: this file is scanned by the rule below like every other.
if m=$(printf '%s\n' "$files" | xargs -r grep -InE 'fd7a:[0-9a-f]{0,4}:' 2>/dev/null); then
    report "Tailscale ULA address (that prefix is a real tailnet, never an example):" "$m"
fi

# 2. CGNAT. 100.64.0.0/10 is where tailnets live. The repository uses 100.64.0.x as
#    its RFC 6598 stand-in, which is the documented shape; anything deeper in the
#    range is somebody's actual host.
if m=$(printf '%s\n' "$files" | xargs -r grep -InE '\b100\.(6[5-9]|[7-9][0-9]|1[0-1][0-9]|12[0-7])\.[0-9]{1,3}\.[0-9]{1,3}\b|\b100\.64\.[1-9][0-9]*\.[0-9]{1,3}\b' 2>/dev/null); then
    report "CGNAT address outside the 100.64.0.x placeholder block:" "$m"
fi

# 3. Absolute home directories. These name a person and their layout, and every one
#    of them is a worse instruction than the relative path it replaced.
if m=$(printf '%s\n' "$files" | xargs -r grep -InE '/home/[a-z_][a-z0-9_-]*/' 2>/dev/null); then
    report "Absolute home path (write a relative path or /path/to/... instead):" "$m"
fi

# 4. Anything the operator names at runtime. Held in a secret rather than committed:
#    a denylist naming the real string would publish the exact thing it exists to
#    keep out. Space-separated extended regexes. Absent locally, which is fine --
#    rules 1-3 are the ones that have actually caught something.
if [ -n "${HX_IDENTIFIER_DENYLIST:-}" ]; then
    for pattern in $HX_IDENTIFIER_DENYLIST; do
        if m=$(printf '%s\n' "$files" | xargs -r grep -InE "$pattern" 2>/dev/null); then
            report "Denylisted identifier:" "$m"
        fi
    done
fi

if [ "$fail" -ne 0 ]; then
    printf '\nTracked files name real infrastructure. Publishing this publishes that.\n'
    exit 1
fi
printf 'No operational identifiers in %s tracked files.\n' "$(printf '%s\n' "$files" | wc -l)"
