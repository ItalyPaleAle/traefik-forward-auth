#!/usr/bin/env bash

# Builds the traefik-forward-auth binary for a single release target, then packages it into an archive.
#
# Usage:
#   BUILD_ID=<id> [BUILD_VERSION=<version>] [BUILD_LDFLAGS=<flags>] [CYCLONEDX_GOMOD=<path>] scripts/build-binaries.sh <target>
#
# Targets:
#   linux-amd64  linux-arm64  linux-armv7
#
# The binary is staged in .bin/traefik-forward-auth-<BUILD_ID>-<target>, and the archive is written to .out as a .tar.gz
# When CYCLONEDX_GOMOD is the path to cyclonedx-gomod, a CycloneDX SBOM for the binary is also written to .out, as traefik-forward-auth-<BUILD_ID>-<target>.cdx.json

set -euo pipefail

# Resolved before anything changes the working directory
script_path="${BASH_SOURCE[0]}"

# Release binaries are statically linked
export CGO_ENABLED=0

usage() {
  sed -n '3,12p' "${script_path}" | sed -E 's/^# ?//'
}

if [[ $# -ne 1 ]]; then
  echo "Error: expected a single target" >&2
  usage >&2
  exit 1
fi

target="$1"

if [[ -z "${BUILD_ID:-}" ]]; then
  echo "Error: the BUILD_ID environment variable is required" >&2
  usage >&2
  exit 1
fi

goarm=""

case "${target}" in
  linux-amd64) goos="linux"; goarch="amd64" ;;
  linux-arm64) goos="linux"; goarch="arm64" ;;
  linux-armv7) goos="linux"; goarch="arm"; goarm="7" ;;
  *)
    echo "Error: unknown target '${target}'" >&2
    usage >&2
    exit 1
    ;;
esac

# Run from the root of the repository, so the paths below do not depend on where the script was invoked from
cd "$(dirname "${script_path}")/.."

name="traefik-forward-auth-${BUILD_ID}-${target}"
stage=".bin/${name}"
binary="${stage}/traefik-forward-auth"

echo -e "\n###\nBuilding ${goos}/${goarch}${goarm:+v${goarm}} into ${stage}\n"

mkdir -p .out "${stage}"

GOOS="${goos}" GOARCH="${goarch}" GOARM="${goarm}" \
  go build \
    -ldflags "${BUILD_LDFLAGS:-}" \
    -o "${binary}" \
    -trimpath \
    ./cmd/traefik-forward-auth

# The SBOM is generated from the module list that Go embeds in the binary, so it matches exactly what was compiled for this target
# cyclonedx-gomod reads the build settings from the binary, but takes the GOOS and GOARCH in package URLs from `go env`, so they must be set to match the build
if [[ -n "${CYCLONEDX_GOMOD:-}" ]]; then
  sbom=".out/${name}.cdx.json"

  echo "Generating SBOM for traefik-forward-auth"
  GOOS="${goos}" GOARCH="${goarch}" GOARM="${goarm}" \
    "${CYCLONEDX_GOMOD}" bin \
      -json \
      -std \
      -version "${BUILD_VERSION:-${BUILD_ID}}" \
      -output "${sbom}" \
      "${binary}"
fi

cp LICENSE.md "${stage}"
cp -r README.md "${stage}"

(cd .bin && tar -czvf "../.out/${name}.tar.gz" "${name}")
