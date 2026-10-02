#!/bin/sh
# ----------------------------------------------------------------------------
# Maven Wrapper Script for Unix/Linux/macOS
# ----------------------------------------------------------------------------

DIR="$(cd "$(dirname "$0")" && pwd)"

if [ -f "$DIR/.mvn/apache-maven-3.9.8/bin/mvn" ]; then
    chmod +x "$DIR/.mvn/apache-maven-3.9.8/bin/mvn"
    exec "$DIR/.mvn/apache-maven-3.9.8/bin/mvn" "$@"
fi

echo "[INFO] Apache Maven not found locally. Downloading Apache Maven 3.9.8..."
mkdir -p "$DIR/.mvn"
curl -s -L -o "$DIR/.mvn/maven.zip" https://repo.maven.apache.org/maven2/org/apache/maven/apache-maven/3.9.8/apache-maven-3.9.8-bin.zip
unzip -q "$DIR/.mvn/maven.zip" -d "$DIR/.mvn"
rm -f "$DIR/.mvn/maven.zip"
chmod +x "$DIR/.mvn/apache-maven-3.9.8/bin/mvn"
exec "$DIR/.mvn/apache-maven-3.9.8/bin/mvn" "$@"
