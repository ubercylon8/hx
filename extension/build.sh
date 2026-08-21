#!/usr/bin/env bash
# Build the hx bridge extension. No Gradle, no Maven, no third-party
# dependencies: this jar enforces scope against client production systems and
# its supply chain is deliberately empty.
set -euo pipefail
cd "$(dirname "$0")"

MONTOYA="${MONTOYA_JAR:-../../burp-lab/probe/lib/montoya-api.jar}"
[ -f "$MONTOYA" ] || { echo "montoya-api.jar not found at $MONTOYA (set MONTOYA_JAR)" >&2; exit 1; }

rm -rf build/classes build/hx-bridge.jar
mkdir -p build/classes
javac --release 21 -nowarn -Xlint:-options \
      -cp "$MONTOYA" -d build/classes \
      $(find src -name '*.java')
printf 'Manifest-Version: 1.0\nImplementation-Title: hx-bridge\n' > build/MANIFEST.MF
jar cfm build/hx-bridge.jar build/MANIFEST.MF -C build/classes .
echo "built $(pwd)/build/hx-bridge.jar"
