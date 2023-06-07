#! /bin/bash

IMAGE="mjkoo/headless-binexport:latest"

set -eo pipefail

PROGNAME=$(basename "$0")

if [ $# -ne 2 ]; then
	echo "USAGE: $PROGNAME PROGRAM OUTFILE" >&2
	exit 1
fi

TMPDIR=$(mktemp -d)
cleanup() {
	rm -rf "$TMPDIR"
}
trap cleanup EXIT

TARGET_BINARY="$1"
OUTPUT_FILE="$2"
TMP_TARGET_BINARY=$(basename "$1")
TMP_OUTPUT_FILE=$(basename "$2")

cp "$TARGET_BINARY" "$TMPDIR/$TMP_TARGET_BINARY"
touch "$TMPDIR/$TMP_OUTPUT_FILE"
chmod 666 "$TMPDIR"/*

docker run --rm -v"$TMPDIR":/workdir -it "$IMAGE" "/workdir/$TMP_TARGET_BINARY" "/workdir/$TMP_OUTPUT_FILE"

cp "$TMPDIR/$TMP_OUTPUT_FILE" "$OUTPUT_FILE"
