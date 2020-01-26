#!/bin/bash
function usage() {
  echo "usage: ./build.sh [--release]"
}

if [[ $# -eq 1 ]] && [[ $1 == "--release" ]]; then
  AGE_VER=$(git describe --tags)
  AGE_VER=${AGE_VER:1}
  go build --ldflags "-X main.version=$(git describe --tags)" -o . filippo.io/age/cmd/...
  exit
elif [[ $# -ne 0 ]]; then
  usage
  exit
elif [[ -z $AGE_VER ]]; then
  AV=$(git describe --tags)
  AGE_VER=${AV%-*-*}
  AGE_COMMIT=${AV##*-g}
  echo AGE_VER
  echo AGE_COMMIT
fi
go build --ldflags "-X main.version=$AGE_VER -X main.commit=$AGE_COMMIT" -o . filippo.io/age/cmd/...
