#!/usr/bin/env bash
# ETC Collector - shared release-signing library (fail-closed).
#
# Source it from a release script:
#     . "$(dirname "$0")/lib/signing.sh"
#     signing_preflight "release"
#
# ...or run it directly as a CI preflight gate:
#     ./scripts/lib/signing.sh preflight
#
# ─── Contract (identical in CI and on a laptop) ──────────────────────────────
#
# Windows signing goes through Azure Trusted Signing (short-lived leaf certs
# issued by a Microsoft-trusted CA, consumed by signtool via the Trusted Signing
# Dlib). The CI job authenticates to Azure with OIDC federation (no stored
# secret), then the azure/trusted-signing-action signs the binary.
#
# The preflight below never performs the signing itself. It only decides the
# MODE for the rest of the workflow: signed, or an audited unsigned fallback.
#
#   AZURE_CLIENT_ID         Application (client) ID of the GitHub Actions
#                           federated identity authorised to sign with the
#                           target certificate profile. Its presence is the
#                           signal that signing is configured end-to-end.
#   ALLOW_UNSIGNED_RELEASE  Explicit, auditable opt-out ("true"/"1"/"yes").
#                           When unset - the default - a release is signed or
#                           it fails. It is never silently unsigned.
#
# The rule this file exists to enforce: **signed, or the build fails.** An
# earlier CI gate (`if: env.CODE_SIGN_PFX != ''`) skipped the signing step when
# the secret was missing and published anyway - green build, unsigned binary.
# This preflight exits non-zero on missing material unless the opt-out is set.
#
# shellcheck shell=bash

# Bash 3.2 compatible (macOS ships 3.2) - no ${var,,}, no associative arrays.

# SIGNING_MODE is set by signing_preflight: "signed" or "unsigned".
SIGNING_MODE="${SIGNING_MODE:-}"

# ─── Output helpers ─────────────────────────────────────────────────────────

signing_log()  { printf '[sign]  %s\n' "$*"; }

signing_warn() {
    printf '[sign]  WARNING: %s\n' "$*" >&2
    [ -n "${GITHUB_ACTIONS:-}" ] && printf '::warning title=Release signing::%s\n' "$*"
    return 0
}

# Hard stop. Sourced under `set -e`, this ends the calling script.
signing_fail() {
    printf '\n[sign]  ERROR: %s\n\n' "$*" >&2
    [ -n "${GITHUB_ACTIONS:-}" ] && printf '::error title=Release signing::%s\n' "$*"
    exit 1
}

signing_lower() { printf '%s' "${1:-}" | tr '[:upper:]' '[:lower:]'; }

signing_truthy() {
    case "$(signing_lower "${1:-}")" in
        true|1|yes|y|on) return 0 ;;
        *)               return 1 ;;
    esac
}

# ─── The guard ───────────────────────────────────────────────────────────────
#
# Decides whether this build signs, refuses, or proceeds under an explicit
# opt-out. Sets SIGNING_MODE. Exits non-zero when the Trusted Signing identity
# is missing and no opt-out was declared.
signing_preflight() {
    ctx="${1:-release}"
    _client="${AZURE_CLIENT_ID:-}"
    _allow="${ALLOW_UNSIGNED_RELEASE:-}"

    if [ -n "$_client" ]; then
        SIGNING_MODE="signed"
        signing_log "Trusted Signing identity present (AZURE_CLIENT_ID set) - the $ctx Windows binary will be signed via Azure Trusted Signing."
        signing_emit_mode
        return 0
    fi

    if signing_truthy "$_allow"; then
        SIGNING_MODE="unsigned"
        signing_warn "ALLOW_UNSIGNED_RELEASE is set - publishing the $ctx UNSIGNED on purpose."
        signing_warn "Windows SmartScreen will warn on this binary and AppLocker/WDAC policies will block it. Artifacts will carry an UNSIGNED marker."
        signing_emit_mode
        return 0
    fi

    signing_fail "$(cat <<EOF
No Trusted Signing identity configured - refusing to publish an unsigned $ctx.

  AZURE_CLIENT_ID : ${_client:+<set>}${_client:-<empty>}

etc-collector runs as root/SYSTEM on customer domain controllers. An unsigned
Windows binary is blocked by AppLocker/WDAC and flagged by SmartScreen, so
shipping one silently is worse than not shipping.

To fix, set the GitHub Actions environment variables that back the OIDC
federation to Azure Trusted Signing (founder action, one-off):

  gh variable set AZURE_CLIENT_ID         --env release --repo <owner>/<repo> --body <app-client-id>
  gh variable set AZURE_TENANT_ID         --env release --repo <owner>/<repo> --body <directory-id>
  gh variable set AZURE_SUBSCRIPTION_ID   --env release --repo <owner>/<repo> --body <subscription-id>
  gh variable set TRUSTED_SIGNING_ENDPOINT --env release --repo <owner>/<repo> --body https://<region>.codesigning.azure.net/
  gh variable set TRUSTED_SIGNING_ACCOUNT --env release --repo <owner>/<repo> --body <account-name>
  gh variable set TRUSTED_SIGNING_PROFILE --env release --repo <owner>/<repo> --body <certificate-profile-name>

To publish unsigned ON PURPOSE (loud, audited, marked in the artifacts):

  gh variable set ALLOW_UNSIGNED_RELEASE --body true --repo <owner>/<repo>
  # or, locally:  ALLOW_UNSIGNED_RELEASE=true ./scripts/lib/signing.sh preflight
EOF
)"
}

# Publish the decision to a GitHub Actions job output when running in CI.
signing_emit_mode() {
    if [ -n "${GITHUB_OUTPUT:-}" ]; then
        printf 'mode=%s\n' "$SIGNING_MODE" >> "$GITHUB_OUTPUT"
    fi
    return 0
}

# ─── Detached provenance signature ───────────────────────────────────────────
#
# checksums.sha256 is fetched over the same channel as the artifacts, so on its
# own it proves nothing against a compromised channel. A detached Sigstore
# signature is verifiable independently, and keyless signing needs no
# pre-provisioned secret - so this half works today, cert or no cert.
signing_sign_checksums() {
    _file="$1"
    # Pas de depot par defaut : la valeur codee ici partait dans la publication
    # et nommait le depot prive. En CI, GITHUB_REPOSITORY est toujours pose ;
    # en local, mieux vaut echouer clairement que signer sous une identite
    # devinee - une signature attribuee au mauvais depot ne vaut rien.
    _repo="${GITHUB_REPOSITORY:-}"
    if [ -z "${COSIGN_IDENTITY:-}" ] && [ -z "$_repo" ]; then
        signing_fail "Cannot sign: set COSIGN_IDENTITY or GITHUB_REPOSITORY."
    fi
    _identity="${COSIGN_IDENTITY:-${GITHUB_SERVER_URL:-https://github.com}/$_repo}"

    [ -f "$_file" ] || signing_fail "Cannot sign checksums: $_file does not exist."

    command -v cosign >/dev/null 2>&1 \
        || signing_fail "cosign is not installed - cannot produce the detached signature for $(basename "$_file")."

    signing_log "Signing $(basename "$_file") with cosign (keyless, Sigstore)..."
    # cosign v3 deprecated --output-signature/--output-certificate: the
    # (former) v2 interface. --bundle is the only mode this version accepts -
    # the old flags now hard-fail with "must specify --bundle with
    # --new-bundle-format" instead of just warning. One file replaces two.
    cosign sign-blob --yes \
        --bundle "${_file}.bundle" \
        "$_file" \
        || signing_fail "cosign sign-blob failed for $(basename "$_file")."

    [ -s "${_file}.bundle" ] || signing_fail "cosign produced an empty signature bundle for $(basename "$_file")."

    signing_log "Detached signature bundle: $(basename "$_file").bundle"
    signing_log "Verify with: cosign verify-blob --bundle $(basename "$_file").bundle --certificate-identity-regexp '^${_identity}' --certificate-oidc-issuer https://token.actions.githubusercontent.com $(basename "$_file")"
}

# Leave a machine-readable marker so an unsigned artifact set announces itself.
signing_write_unsigned_marker() {
    _dir="$1"
    [ -d "$_dir" ] || return 0
    cat > "$_dir/UNSIGNED" <<EOF
This release was published WITHOUT an Authenticode signature.

ALLOW_UNSIGNED_RELEASE was set explicitly at build time. The Windows binary in
this release is not code-signed: SmartScreen will warn on it and AppLocker/WDAC
policies will block it.

Built: ${GITHUB_REF:-local} ${GITHUB_SHA:-}
EOF
    signing_warn "Wrote $_dir/UNSIGNED marker."
}

# ─── Direct invocation (CI preflight) ────────────────────────────────────────

if [ "${BASH_SOURCE[0]}" = "$0" ]; then
    set -euo pipefail
    case "${1:-preflight}" in
        preflight) signing_preflight "${2:-release}" ;;
        *)         signing_fail "Unknown subcommand: $1 (expected: preflight)" ;;
    esac
fi
