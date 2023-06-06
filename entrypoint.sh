#! /bin/sh

if [ $# -ne 2 ]; then
	echo "USAGE: $0 PROGRAM OUTFILE" >&2
        exit 2
fi

TARGET_BINARY=$1
OUTPUT_FILE=$2
PROJECT_NAME=$(basename $TARGET_BINARY)

/opt/jre/bin/java \
	-Xmx2048M -Xshare:off \
	-Djava.awt.headless=true \
	--add-opens java.base/java.net=ALL-UNNAMED \
	-jar /opt/ghidra/ghidra.jar /tmp $PROJECT_NAME \
	-deleteProject -readOnly -import $TARGET_BINARY \
	-scriptPath /opt/ghidra/ghidra_scripts \
	-postScript HeadlessBinExport.java $OUTPUT_FILE
