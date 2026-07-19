#!/usr/bin/env sh
set -eu

if ! command -v mvn >/dev/null 2>&1; then
    echo "Maven 3.8 or newer is required to build the Java slicer" >&2
    exit 1
fi

mvn --batch-mode --file java-slicer/pom.xml clean verify

JAR="java-slicer/target/lamd-slicer.jar"
if [ ! -f "$JAR" ]; then
    echo "Expected shaded slicer JAR was not created: $JAR" >&2
    exit 1
fi

echo "LAMD slicer built at $JAR"
