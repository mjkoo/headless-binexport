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
