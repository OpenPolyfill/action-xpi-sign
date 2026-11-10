#!/usr/bin/env bash
set -euo pipefail

source_file=${XPI_SOURCE:?Missing source}
artifacts=${XPI_ARTIFACTS:-signed}
private_key=${XPI_PRIVATE_KEY:?Missing privateKey}
certificate=${XPI_CERTIFICATE:?Missing certificate}
action_root=${XPI_ACTION_ROOT:?Missing action root}

if [[ ! -f "$source_file" || "$source_file" != *.xpi ]]; then
  echo 'source must point to an existing .xpi file' >&2
  exit 1
fi

for executable in node openssl zip unzip; do
  command -v "$executable" >/dev/null || {
    echo "Missing executable: $executable" >&2
    exit 1
  }
done

umask 077
temp_dir=$(mktemp -d "${RUNNER_TEMP:-${TMPDIR:-/tmp}}/xpi-sign.XXXXXXXX")
cleanup() {
  rm -f -- "$temp_dir/private.pem" "$temp_dir/certificate.pem"
  rmdir -- "$temp_dir"
}
trap cleanup EXIT

if [[ -f "$private_key" ]]; then
  key_file=$private_key
else
  key_file="$temp_dir/private.pem"
  printf '%s\n' "$private_key" > "$key_file"
fi

if [[ -f "$certificate" ]]; then
  cert_file=$certificate
else
  cert_file="$temp_dir/certificate.pem"
  printf '%s\n' "$certificate" > "$cert_file"
fi

openssl pkey -in "$key_file" -noout >/dev/null
openssl x509 -in "$cert_file" -noout >/dev/null

mkdir -p -- "$artifacts"
target="$artifacts/$(basename "$source_file")"
args=( "$source_file" "$key_file" "$cert_file" "$target" )
if [[ -n "${XPI_EXPECTED_ID:-}" ]]; then
  args+=( "$XPI_EXPECTED_ID" )
fi

node "$action_root/scripts/sign-xpi.mjs" "${args[@]}"

target=$(realpath -- "$target")
if [[ -n "${GITHUB_OUTPUT:-}" ]]; then
  printf 'target=%s\n' "$target" >> "$GITHUB_OUTPUT"
fi
echo "Signed XPI: $target"
