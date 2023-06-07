ARG VCS_REF="unknown"
ARG BUILD_DATE="1970-01-01"

ARG GRADLE_IMAGE=gradle:jdk17-alpine
ARG BASE_IMAGE=alpine:3.18

ARG GHIDRA_RELEASE_URL=https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_10.3_build/ghidra_10.3_PUBLIC_20230510.zip
ARG BINEXPORT_REPO=https://github.com/google/binexport.git
ARG BINEXPORT_REV=27256a2939aff6841acabf0300368b412e199dcf

FROM $GRADLE_IMAGE as ghidra-source

ARG GHIDRA_RELEASE_URL

RUN apk add --no-cache bash curl

WORKDIR /src

RUN curl -Lo ghidra.zip $GHIDRA_RELEASE_URL && \
    unzip ghidra.zip && \
    mv ghidra_* ghidra && \
    rm -f ghidra.zip

FROM ghidra-source as binexport-build

ARG BINEXPORT_REPO
ARG BINEXPORT_REV

ENV GHIDRA_INSTALL_DIR=/src/ghidra

RUN git clone $BINEXPORT_REPO binexport && \
    cd binexport/java && \
    git checkout $BINEXPORT_REV && \
    gradle

RUN unzip -d /src/ghidra/Ghidra/Extensions binexport/java/dist/*.zip

FROM binexport-build as ghidra-build

COPY BuildGhidraJarScript.java ghidra/Ghidra/Features/Base/ghidra_scripts/BuildGhidraJarScript.java

RUN /src/ghidra/support/analyzeHeadless \
    /tmp tmp -deleteProject -readOnly \
    -scriptPath /src/ghidra/Ghidra/Features/Base/ghidra_scripts \
    -preScript BuildGhidraJarScript.java && \
    chmod 644 /src/ghidra/ghidra.jar

FROM $GRADLE_IMAGE as jre-build

RUN apk add --no-cache binutils

RUN jlink --verbose --strip-debug --no-header-files --no-man-pages \
    --module-path /opt/java/openjdk/jmods \
    --add-modules java.base,java.desktop,java.compiler,java.management,java.naming,jdk.compiler,jdk.zipfs \ 
    --output /opt/jre

FROM $BASE_IMAGE

ARG VCS_REF
ARG BUILD_DATE

LABEL maintainer="mjkoo90@gmail.com" \
    org.opencontainers.image.title="Headless BinExport" \
    org.opencontainers.image.description="Create an exported disassembly of a binary with Ghidra and BinExport " \
    org.opencontainers.image.authors="Maxwell Koo <mjkoo90@gmail.com>" \
    org.opencontainers.image.vendor="Maxwell Koo <mjkoo90@gmail.com>" \
    org.opencontainers.image.version="1.0.0" \
    org.opencontainers.image.licenses="MIT" \
    org.opencontainers.image.documentation="https://github.com/mjkoo/headless-binexport" \
    org.opencontainers.image.url="https://github.com/mjkoo/headless-binexport" \
    org.opencontainers.image.source="https://github.com/mjkoo/headless-binexport" \
    org.opencontainers.image.revision=$VCS_REF \
    org.opencontainers.image.created=$BUILD_DATE

RUN apk add --no-cache gcompat libstdc++ fontconfig ttf-dejavu

COPY --from=jre-build /opt/jre /opt/jre
COPY --from=ghidra-build /src/ghidra/ghidra.jar /opt/ghidra/ghidra.jar
COPY HeadlessBinExport.java /opt/ghidra/ghidra_scripts/HeadlessBinExport.java
COPY entrypoint.sh /

RUN adduser --gecos "" --disabled-password user
USER user
WORKDIR /home/user

ENV PATH=/opt/jre/bin:$PATH

ENTRYPOINT ["/entrypoint.sh"]
