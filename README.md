# headless-binexport

[![Build](https://github.com/mjkoo/headless-binexport/actions/workflows/docker.yaml/badge.svg)](https://github.com/mjkoo/headless-binexport/actions/workflows/docker.yaml)

A Dockerfile + wrapper script to do one-step automatic exporting of a target binary's disasssembly via [Ghidra](https://github.com/NationalSecurityAgency/ghidra) and [BinExport](https://github.com/google/binexport)

## Usage

The docker image is pushed via Github Actions to `docker.io/mjkoo/headless-binexport`.
Can use this directly if desired, or can use the small included wrapper script.

`./headless-binexport.sh /bin/bash bash.BinExport`

## BinExport Format

Please check out the [BinExport](https://github.com/google/binexport) repo for more information on the exported protobuf format.
