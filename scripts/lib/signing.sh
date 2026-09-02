#!/usr/bin/env bash
# ETC Collector — shared release-signing library (fail-closed).
#
# Source it from a release script:
#     . "$(dirname "$0")/lib/signing.sh"
#     signing_preflight "Pro release"
#
# ...or run it directly as a CI preflight gate:
#     ./scripts/lib/signing.sh preflight
#
# ─── Contract (identical in CI and on a laptop) ──────────────────────────────
#
#   CODE_SIGN_PFX           The PKCS#12 code-signing bundle. Either a path to a
#                           .pfx/.p12 file, or the base64 of one. A .pfx is
#                           binary, so as a CI secret it MUST be stored base64:
#                               base64 -w0 cert.pfx | gh secret set CODE_SIGN_PFX
#   CODE_SIGN_PASSWORD      Password for that bundle.
#   ALLOW_UNSIGNED_RELEASE  Explicit, auditable opt-out ("true"/"1"/"yes").
#                           When unset — the default — a release is signed or
#                           it fails. It is never silently unsigned.
#
# The rule this file exists to enforce: **signed, or the build fails.** The
# previous CI gate (`if: env.CODE_SIGN_PFX != ''`) skipped the signing step when
# the secret was missing and published anyway — green build, unsigned binary.
#
# shellcheck shell=bash

# Bash 3.2 compatible (macOS ships 3.2) — no ${var,,}, no associative arrays.

SIGNING_TIMESTAMP_URLS="${SIGNING_TIMESTAMP_URLS:-http://timestamp.digicert.com http://timestamp.sectigo.com}"
SIGNING_NAME="${SIGNING_NAME:-ETC Collector}"
SIGNING_URL="${SIGNING_URL:-https://etcsec.com}"

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

# base64 decode, portable across GNU coreutils (-d) and BSD/macOS (-D).
signing_b64_decode() {
    if base64 -d </dev/null >/dev/null 2>&1; then
        base64 -d
    elif base64 -D </dev/null >/dev/null 2>&1; then
        base64 -D
    else
        openssl base64 -d -A
    fi
}

# ─── The guard ───────────────────────────────────────────────────────────────
#
# Decides whether this build signs, refuses, or proceeds under an explicit
# opt-out. Sets SIGNING_MODE. Exits non-zero when signing material is missing
# and no opt-out was declared.
signing_preflight() {
    ctx="${1:-release}"
    _pfx="${CODE_SIGN_PFX:-}"
    _pass="${CODE_SIGN_PASSWORD:-}"
    _allow="${ALLOW_UNSIGNED_RELEASE:-}"

    # Half-configured is always fatal — even with the opt-out set. It means
    # somebody believes signing is on when it is not, which is the exact
    # failure mode this ticket exists to kill.
    if [ -n "$_pfx" ] && [ -z "$_pass" ]; then
        signing_fail "CODE_SIGN_PFX is set but CODE_SIGN_PASSWORD is empty — refusing to guess. Set both, or set ALLOW_UNSIGNED_RELEASE=true to publish deliberately unsigned."
    fi
    if [ -z "$_pfx" ] && [ -n "$_pass" ]; then
        signing_fail "CODE_SIGN_PASSWORD is set but CODE_SIGN_PFX is empty — refusing to guess. Set both, or set ALLOW_UNSIGNED_RELEASE=true to publish deliberately unsigned."
    fi

    if [ -n "$_pfx" ] && [ -n "$_pass" ]; then
        SIGNING_MODE="signed"
        signing_log "Signing material present — the $ctx Windows binary will be Authenticode-signed."
        signing_emit_mode
        return 0
    fi

    if signing_truthy "$_allow"; then
        SIGNING_MODE="unsigned"
        signing_warn "ALLOW_UNSIGNED_RELEASE is set — publishing the $ctx UNSIGNED on purpose."
        signing_warn "Windows SmartScreen will warn on this binary and AppLocker/WDAC policies will block it. Artifacts will carry an UNSIGNED marker."
        signing_emit_mode
        return 0
    fi

    signing_fail "$(cat <<EOF
No code-signing material — refusing to publish an unsigned $ctx.

  CODE_SIGN_PFX      : ${_pfx:+<set>}${_pfx:-<empty>}
  CODE_SIGN_PASSWORD : ${_pass:+<set>}${_pass:-<empty>}

etc-collector runs as root/SYSTEM on customer domain controllers. An unsigned
Windows binary is blocked by AppLocker/WDAC and flagged by SmartScreen, so
shipping one silently is worse than not shipping.

To fix, provision the certificate (founder action):

  base64 -w0 codesign.pfx | gh secret set CODE_SIGN_PFX  --repo <owner>/<repo>
  printf '%s' '<pfx-password>'  | gh secret set CODE_SIGN_PASSWORD --repo <owner>/<repo>

To publish unsigned ON PURPOSE (loud, audited, marked in the artifacts):

  gh variable set ALLOW_UNSIGNED_RELEASE --body true --repo <owner>/<repo>
  # or, locally:  ALLOW_UNSIGNED_RELEASE=true ./scripts/release-pro.sh
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

# ─── PKCS#12 materialisation ─────────────────────────────────────────────────
#
# osslsigncode's -pkcs12 wants a FILE PATH. The old workflow handed it the raw
# secret value, so signing would have failed the first time the secret was
# actually added. Accept either a path or base64, always end up with a file.
signing_materialize_pfx() {
    dest="$1"
    _pfx="${CODE_SIGN_PFX:-}"

    [ -n "$_pfx" ] || signing_fail "signing_materialize_pfx called with an empty CODE_SIGN_PFX"

    if [ -f "$_pfx" ]; then
        cp "$_pfx" "$dest"
    else
        printf '%s' "$_pfx" | tr -d '[:space:]' | signing_b64_decode > "$dest" 2>/dev/null \
            || signing_fail "CODE_SIGN_PFX is neither a readable file path nor valid base64. Store it as: base64 -w0 codesign.pfx | gh secret set CODE_SIGN_PFX"
    fi

    [ -s "$dest" ] || signing_fail "CODE_SIGN_PFX decoded to an empty file — the secret is corrupt or truncated."
    chmod 600 "$dest"
}

signing_shred() {
    for _f in "$@"; do
        [ -f "$_f" ] || continue
        if command -v shred >/dev/null 2>&1; then
            shred -u "$_f" 2>/dev/null || rm -f "$_f"
        else
            rm -f "$_f"
        fi
    done
    return 0
}

# ─── Authenticode ────────────────────────────────────────────────────────────

# signing_sign_windows <path-to-exe> <path-to-pfx>
signing_sign_windows() {
    exe="$1"
    pfx_path="$2"

    [ -f "$exe" ] || signing_fail "Cannot sign: $exe does not exist."
    command -v osslsigncode >/dev/null 2>&1 \
        || signing_fail "osslsigncode is not installed — cannot sign $(basename "$exe"). Install it (apt-get install osslsigncode / brew install osslsigncode)."

    _out="${exe}.signing"
    _signed=false

    # Timestamping is the flakiest part of the chain and an untimestamped
    # signature dies with the certificate, so retry across servers.
    for _ts in $SIGNING_TIMESTAMP_URLS; do
        for _attempt in 1 2; do
            signing_log "Signing $(basename "$exe") (timestamp: $_ts, attempt $_attempt)..."
            if osslsigncode sign \
                -pkcs12 "$pfx_path" \
                -pass "${CODE_SIGN_PASSWORD:-}" \
                -n "$SIGNING_NAME" \
                -i "$SIGNING_URL" \
                -ts "$_ts" \
                -h sha256 \
                -in "$exe" \
                -out "$_out" >/dev/null 2>&1
            then
                _signed=true
                break 2
            fi
            rm -f "$_out"
            sleep 5
        done
        signing_warn "Timestamp server $_ts did not respond — trying the next one."
    done

    [ "$_signed" = true ] \
        || signing_fail "osslsigncode failed to sign $(basename "$exe") against every timestamp server ($SIGNING_TIMESTAMP_URLS)."

    mv "$_out" "$exe"
    signing_verify_windows "$exe"
    signing_log "Signed and verified: $(basename "$exe")"
}

# Assert the binary really carries a signature. Without this, a signing tool
# that fails quietly (or is silently a no-op) still yields a green build — the
# same class of bug as the old skip-on-missing-secret gate.
signing_verify_windows() {
    exe="$1"

    command -v osslsigncode >/dev/null 2>&1 \
        || signing_fail "osslsigncode is not installed — cannot verify $(basename "$exe")."

    _v="$(osslsigncode verify -in "$exe" 2>&1 || true)"

    if printf '%s' "$_v" | grep -qi "no signature found"; then
        signing_fail "Post-sign verification FAILED — $(basename "$exe") carries NO signature. Refusing to publish it."
    fi

    # Require positive evidence of a signature, not merely the absence of the
    # error string (osslsigncode wording varies between versions).
    if ! printf '%s' "$_v" | grep -qiE "signature index|number of (verified )?signatures|signature verification: ok"; then
        signing_fail "Post-sign verification of $(basename "$exe") produced no recognisable signature evidence. Refusing to publish it. osslsigncode said: $(printf '%s' "$_v" | head -5 | tr '\n' ' ')"
    fi

    # Chain trust is deliberately NOT asserted here: the Authenticode root is
    # often absent from a Linux CI trust store, and Windows is the authority on
    # that. What must hold in CI is that a signature is present at all.
    if printf '%s' "$_v" | grep -qi "signature verification: failed"; then
        signing_warn "$(basename "$exe") is signed, but osslsigncode could not validate the chain on this host (usually a missing Authenticode root in the CI trust store, not a bad signature). Validate on Windows with: Get-AuthenticodeSignature"
    fi
}

# ─── Detached provenance signature ───────────────────────────────────────────
#
# checksums.sha256 is fetched over the same channel as the artifacts, so on its
# own it proves nothing against a compromised channel. A detached Sigstore
# signature is verifiable independently, and keyless signing needs no
# pre-provisioned secret — so this half works today, cert or no cert.
signing_sign_checksums() {
    _file="$1"
    # Pas de depot par defaut : la valeur codee ici partait dans la publication
    # et nommait le depot prive. En CI, GITHUB_REPOSITORY est toujours pose ;
    # en local, mieux vaut echouer clairement que signer sous une identite
    # devinee — une signature attribuee au mauvais depot ne vaut rien.
    _repo="${GITHUB_REPOSITORY:-}"
    if [ -z "${COSIGN_IDENTITY:-}" ] && [ -z "$_repo" ]; then
        signing_fail "Cannot sign: set COSIGN_IDENTITY or GITHUB_REPOSITORY."
    fi
    _identity="${COSIGN_IDENTITY:-${GITHUB_SERVER_URL:-https://github.com}/$_repo}"

    [ -f "$_file" ] || signing_fail "Cannot sign checksums: $_file does not exist."

    command -v cosign >/dev/null 2>&1 \
        || signing_fail "cosign is not installed — cannot produce the detached signature for $(basename "$_file")."

    signing_log "Signing $(basename "$_file") with cosign (keyless, Sigstore)..."
    # cosign v3 deprecated --output-signature/--output-certificate: the
    # (former) v2 interface. --bundle is the only mode this version accepts —
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
