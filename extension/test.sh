#!/usr/bin/env bash
# Run the extension's own tests. A tiny hand-rolled runner: adding JUnit would
# mean adding a dependency and a build tool, which is what this design avoids.
set -euo pipefail
cd "$(dirname "$0")"

MONTOYA="${MONTOYA_JAR:-../../burp-lab/probe/lib/montoya-api.jar}"
rm -rf build/test-classes
mkdir -p build/test-classes
javac --release 21 -nowarn -Xlint:-options \
      -cp "$MONTOYA" -d build/test-classes \
      $(find src test -name '*.java')

# ADD A NEW TEST CLASS HERE, on its own line, and nowhere else. A hand-rolled
# runner has no discovery: a class nobody lists is a file that compiles, never
# runs, and reads in review exactly like a test that passes.
CLASSES=(
    hx.bridge.CodecTest
    hx.bridge.BridgeClientTest
    hx.policy.PolicyTest
    hx.policy.LimiterTest
    hx.policy.DistressTest
    hx.send.RedactorTest
    hx.send.HaltSwitchTest
)

# Every class runs, whatever the ones before it did, and the run still exits
# non-zero. This used to be five bare `java` lines under `set -e`, which stopped
# at the FIRST failing class: one ordinary failed check in CodecTest ran 95 of
# 905 checks and never executed the other 810. A sabotage count taken that way
# measures how far the runner got, not how many checks failed -- and the counts
# on this branch are the evidence the design decisions were made from.
#
# `timeout` is the backstop for the other truncation: a class that blocks
# forever prints no summary line and returns no exit code at all, which under
# `./test.sh | grep -c FAIL` reads as zero failures. The per-operation deadlines
# inside BridgeClientTest are the real guard; this bounds anything that has none.
rc=0
for c in "${CLASSES[@]}"; do
    timeout 300 java -cp "build/test-classes:$MONTOYA" "$c" || rc=1
done
exit "$rc"
