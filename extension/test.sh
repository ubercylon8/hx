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
java -cp "build/test-classes:$MONTOYA" hx.bridge.CodecTest
