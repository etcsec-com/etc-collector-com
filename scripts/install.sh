#!/usr/bin/env bash
# NOTE 2026-09-01 — ce script vivait dans scripts/ du depot PRIVE, donc il
# n'etait publie nulle part : les quatre URL d'installation documentees
# rendaient 403 ou 404, et le produit n'avait aucun chemin d'installation
# atteignable. Il est desormais sous public/scripts/, donc publie.
# L'URL ci-dessous est le brut du depot public : elle est moins jolie que
# get.etcsec.com, mais elle repond. Quand get.etcsec.com sera retabli, il
# suffira de le faire pointer ici et de remplacer cette URL.
#
# ETC Collector — Standalone Installer for Linux
# https://etcsec.com
#
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/etcsec-com/etc-collector-com/main/scripts/install.sh | sudo bash
#   curl -fsSL https://raw.githubusercontent.com/etcsec-com/etc-collector-com/main/scripts/install.sh | sudo bash -s -- --version 2.8.0
#   curl -fsSL https://raw.githubusercontent.com/etcsec-com/etc-collector-com/main/scripts/install.sh | sudo bash -s -- --uninstall
#
set -euo pipefail

# ─── Constants ───────────────────────────────────────────────────────────────

BASE_URL="https://get.etcsec.com/downloads"
BIN_DIR="/usr/local/bin"
CONFIG_DIR="/etc/etc-collector"
DATA_DIR="/var/lib/etc-collector"
SERVICE_DIR="/etc/systemd/system"
SERVICE_NAME="etcsec-collector"
SERVICE_FILE="etcsec-collector.service"
BINARY_NAME="etc-collector"

# Provenance: checksums.sha256 arrives over the same channel as the tarball, so
# on its own it does not survive a compromised mirror. The detached Sigstore
# signature published beside it does — it is verifiable against the release
# workflow's identity, independently of where the bytes came from.
# L'identite attendue n'est PAS codee ici. Elle nommait le depot de
# developpement, qui est prive : un installeur public n'a pas a reveler ou le
# produit est construit, et un lecteur n'aurait de toute facon pas pu verifier
# ce nom. Elle se pose par l'environnement quand une release est signee.
# v3.2.0 est publiee NON SIGNEE : il n'y a rien a verifier, et --require-signature
# le dit clairement plutot que d'echouer sur une identite devinee.
COSIGN_IDENTITY_REGEXP="${COSIGN_IDENTITY_REGEXP:-}"
COSIGN_OIDC_ISSUER="https://token.actions.githubusercontent.com"

# ─── Color helpers ───────────────────────────────────────────────────────────

if [ -t 1 ] && [ -t 2 ]; then
    RED='\033[0;31m'
    GREEN='\033[0;32m'
    YELLOW='\033[0;33m'
    CYAN='\033[0;36m'
    BOLD='\033[1m'
    NC='\033[0m'
else
    RED='' GREEN='' YELLOW='' CYAN='' BOLD='' NC=''
fi

info()  { printf "  ${CYAN}[*]${NC} %s\n" "$*"; }
ok()    { printf "  ${GREEN}[OK]${NC} %s\n" "$*"; }
warn()  { printf "  ${YELLOW}[--]${NC} %s\n" "$*" >&2; }
err()   { printf "  ${RED}[!!]${NC} %s\n" "$*" >&2; }
die()   { err "$@"; exit 1; }

banner() {
    printf "\n"
    printf "  ${BOLD}ETC Collector${NC} — Identity Security Audit\n"
    printf "  ──────────────────────────────────────────\n"
    printf "\n"
}

# ─── Parse arguments ────────────────────────────────────────────────────────

REQUESTED_VERSION=""
NO_SERVICE=false
DO_UNINSTALL=false
DO_PURGE=false
REQUIRE_SIGNATURE=false

while [ $# -gt 0 ]; do
    case "$1" in
        --version)
            shift
            [ $# -eq 0 ] && die "--version requires a value"
            REQUESTED_VERSION="$1"
            ;;
        --no-service)
            NO_SERVICE=true
            ;;
        --uninstall)
            DO_UNINSTALL=true
            ;;
        --purge)
            DO_PURGE=true
            ;;
        --require-signature)
            REQUIRE_SIGNATURE=true
            ;;
        --help|-h)
            cat <<'USAGE'
ETC Collector Installer

Usage:
  curl -fsSL https://raw.githubusercontent.com/etcsec-com/etc-collector-com/main/scripts/install.sh | sudo bash
  curl -fsSL https://raw.githubusercontent.com/etcsec-com/etc-collector-com/main/scripts/install.sh | sudo bash -s -- [OPTIONS]

Options:
  --version VERSION    Install a specific version (default: latest)
  --no-service         Skip systemd service installation
  --uninstall          Uninstall ETC Collector
  --purge              With --uninstall: also remove config and data
  --require-signature  Abort unless the detached Sigstore signature on
                       checksums.sha256 verifies (needs cosign installed)
  --help               Show this help message

Examples:
  # Install latest version
  curl -fsSL https://raw.githubusercontent.com/etcsec-com/etc-collector-com/main/scripts/install.sh | sudo bash

  # Install specific version
  curl -fsSL https://raw.githubusercontent.com/etcsec-com/etc-collector-com/main/scripts/install.sh | sudo bash -s -- --version 2.8.0

  # Uninstall and remove all data
  curl -fsSL https://raw.githubusercontent.com/etcsec-com/etc-collector-com/main/scripts/install.sh | sudo bash -s -- --uninstall --purge
USAGE
            exit 0
            ;;
        *)
            die "Unknown option: $1 (use --help for usage)"
            ;;
    esac
    shift
done

# ─── Preflight checks ───────────────────────────────────────────────────────

banner

# Root check
if [ "$(id -u)" -ne 0 ]; then
    die "This script must be run as root. Use: sudo bash install.sh"
fi

# OS check
OS="$(uname -s)"
if [ "$OS" != "Linux" ]; then
    die "This installer supports Linux only. Detected: $OS"
fi

# Architecture detection
MACHINE="$(uname -m)"
case "$MACHINE" in
    x86_64)  ARCH="amd64" ;;
    aarch64) ARCH="arm64" ;;
    *)       die "Unsupported architecture: $MACHINE. ETC Collector supports x86_64 (amd64) and aarch64 (arm64)." ;;
esac

info "System: Linux $MACHINE ($ARCH)"

# Dependency checks
DOWNLOADER=""
if command -v curl >/dev/null 2>&1; then
    DOWNLOADER="curl"
elif command -v wget >/dev/null 2>&1; then
    DOWNLOADER="wget"
else
    die "curl or wget is required. Install one and retry."
fi

command -v tar >/dev/null 2>&1 || die "tar is required but not found."
command -v sha256sum >/dev/null 2>&1 || die "sha256sum is required but not found."

# systemd check (unless --no-service)
if [ "$NO_SERVICE" = false ] && [ "$DO_UNINSTALL" = false ]; then
    if ! command -v systemctl >/dev/null 2>&1; then
        warn "systemctl not found. Skipping service installation."
        NO_SERVICE=true
    fi
fi

# ─── Download helper ────────────────────────────────────────────────────────

download() {
    local url="$1"
    local dest="$2"

    if [ "$DOWNLOADER" = "curl" ]; then
        curl -fsSL --retry 3 --retry-delay 2 -o "$dest" "$url"
    else
        wget -q --tries=3 -O "$dest" "$url"
    fi
}

# ─── Uninstall ───────────────────────────────────────────────────────────────

if [ "$DO_UNINSTALL" = true ]; then
    info "Uninstalling ETC Collector..."

    # Stop and disable service
    if command -v systemctl >/dev/null 2>&1; then
        systemctl stop "$SERVICE_NAME" 2>/dev/null || true
        systemctl disable "$SERVICE_NAME" 2>/dev/null || true
        rm -f "$SERVICE_DIR/$SERVICE_FILE"
        systemctl daemon-reload 2>/dev/null || true
        ok "Service removed"
    fi

    # Remove binary
    if [ -f "$BIN_DIR/$BINARY_NAME" ]; then
        rm -f "$BIN_DIR/$BINARY_NAME"
        ok "Binary removed"
    else
        warn "Binary not found at $BIN_DIR/$BINARY_NAME"
    fi

    # Purge config and data
    if [ "$DO_PURGE" = true ]; then
        rm -rf "$CONFIG_DIR"
        rm -rf "$DATA_DIR"
        ok "Config and data directories removed"
    else
        info "Config and data preserved in $CONFIG_DIR and $DATA_DIR"
        info "Use --purge to remove everything."
    fi

    printf "\n  ${GREEN}ETC Collector uninstalled.${NC}\n\n"
    exit 0
fi

# ─── Temp directory with cleanup ─────────────────────────────────────────────

TMPDIR="$(mktemp -d)"
cleanup() { rm -rf "$TMPDIR"; }
trap cleanup EXIT

# ─── Resolve version ────────────────────────────────────────────────────────

if [ -n "$REQUESTED_VERSION" ]; then
    # Strip leading 'v' if present
    VERSION="${REQUESTED_VERSION#v}"
    DOWNLOAD_URL="$BASE_URL/etc-collector-${VERSION}-linux-${ARCH}.tar.gz"
    CHECKSUMS_URL="$BASE_URL/checksums.sha256"
    info "Requested version: $VERSION"
else
    info "Fetching latest version..."

    download "$BASE_URL/latest.json" "$TMPDIR/latest.json" \
        || die "Failed to fetch latest.json from $BASE_URL/latest.json"

    VERSION=$(grep '"version"' "$TMPDIR/latest.json" | sed 's/.*: *"\(.*\)".*/\1/' | tr -d ' ,')
    DOWNLOAD_URL=$(grep "\"linux-${ARCH}\"" "$TMPDIR/latest.json" | sed 's/.*: *"\(.*\)".*/\1/' | tr -d ' ,')
    CHECKSUMS_URL=$(grep '"checksums"' "$TMPDIR/latest.json" | sed 's/.*: *"\(.*\)".*/\1/' | tr -d ' ,')

    [ -z "$VERSION" ] && die "Failed to parse version from latest.json"
    [ -z "$DOWNLOAD_URL" ] && die "No download URL found for linux-$ARCH in latest.json"
    [ -z "$CHECKSUMS_URL" ] && die "No checksums URL found in latest.json"

    info "Latest version: $VERSION"
fi

# ─── Detect existing installation ───────────────────────────────────────────

UPGRADING=false
SERVICE_WAS_RUNNING=false
CURRENT_VERSION=""

if [ -x "$BIN_DIR/$BINARY_NAME" ]; then
    CURRENT_VERSION=$("$BIN_DIR/$BINARY_NAME" version 2>/dev/null | head -1 | awk '{print $NF}' || echo "unknown")
    if [ "$CURRENT_VERSION" = "$VERSION" ]; then
        info "ETC Collector $VERSION is already installed. Re-installing..."
    else
        info "Upgrading ETC Collector: $CURRENT_VERSION -> $VERSION"
        UPGRADING=true
    fi
fi

# ─── Download and verify ────────────────────────────────────────────────────

TARBALL="etc-collector-${VERSION}-linux-${ARCH}.tar.gz"

info "Downloading $TARBALL..."
download "$DOWNLOAD_URL" "$TMPDIR/$TARBALL" \
    || die "Failed to download $DOWNLOAD_URL"

info "Downloading checksums..."
download "$CHECKSUMS_URL" "$TMPDIR/checksums.sha256" \
    || die "Failed to download checksums from $CHECKSUMS_URL"

# ─── Verify the detached signature on checksums.sha256 ──────────────────────
#
# Order matters: authenticate checksums.sha256 FIRST, then trust it to
# authenticate the tarball. Verifying the tarball against an unauthenticated
# checksum file only proves the download was not corrupted in transit.
#
# cosign v3 deprecated the separate --certificate/--signature files in favour
# of a single --bundle file (same change as scripts/lib/signing.sh's signing
# side) — one download, one flag, matching what the release actually publishes.
BUNDLE_URL="${CHECKSUMS_URL}.bundle"

if download "$BUNDLE_URL" "$TMPDIR/checksums.sha256.bundle" 2>/dev/null; then

    if [ -z "$COSIGN_IDENTITY_REGEXP" ]; then
        if [ "$REQUIRE_SIGNATURE" = true ]; then
            die "--require-signature was given but this build has no expected signing identity.\n  Set COSIGN_IDENTITY_REGEXP to the identity you expect, or install without it."
        fi
        warn "No expected signing identity configured — skipping provenance check."
    elif command -v cosign >/dev/null 2>&1; then
        info "Verifying release signature..."
        if cosign verify-blob \
                --bundle "$TMPDIR/checksums.sha256.bundle" \
                --certificate-identity-regexp "$COSIGN_IDENTITY_REGEXP" \
                --certificate-oidc-issuer "$COSIGN_OIDC_ISSUER" \
                "$TMPDIR/checksums.sha256" >/dev/null 2>&1; then
            ok "Release signature verified (Sigstore)"
        else
            # A signature that is present but does not verify is never benign.
            die "Release signature verification FAILED!\n  checksums.sha256 does not match its published signature.\n  This can indicate a tampered mirror. Aborting."
        fi
    elif [ "$REQUIRE_SIGNATURE" = true ]; then
        die "--require-signature was given but cosign is not installed.\n  Install it: https://docs.sigstore.dev/cosign/installation/"
    else
        warn "cosign not installed — skipping signature verification (checksum still enforced)."
        warn "For full provenance: install cosign and re-run with --require-signature"
    fi

elif [ "$REQUIRE_SIGNATURE" = true ]; then
    die "--require-signature was given but no detached signature is published for this release.\n  Releases before v3.1.40, and v3.2.0, are published unsigned."
else
    warn "No detached signature published for this release — skipping provenance check."
fi

info "Verifying checksum..."
EXPECTED=$(grep "$TARBALL" "$TMPDIR/checksums.sha256" | awk '{print $1}')
if [ -z "$EXPECTED" ]; then
    die "Checksum for $TARBALL not found in checksums.sha256"
fi

ACTUAL=$(sha256sum "$TMPDIR/$TARBALL" | awk '{print $1}')
if [ "$EXPECTED" != "$ACTUAL" ]; then
    die "Checksum verification FAILED!\n  Expected: $EXPECTED\n  Actual:   $ACTUAL\n  This could indicate a corrupted download or tampered file."
fi
ok "Checksum verified"

# ─── Extract ─────────────────────────────────────────────────────────────────

info "Extracting..."
tar xzf "$TMPDIR/$TARBALL" -C "$TMPDIR"

# The tarball contains: etc-collector-{VERSION}-linux-{ARCH}/etc-collector
EXTRACTED_BIN="$TMPDIR/etc-collector-${VERSION}-linux-${ARCH}/$BINARY_NAME"
if [ ! -f "$EXTRACTED_BIN" ]; then
    die "Binary not found in archive at expected path: etc-collector-${VERSION}-linux-${ARCH}/$BINARY_NAME"
fi

# ─── Stop service if upgrading ───────────────────────────────────────────────

if [ "$UPGRADING" = true ] && command -v systemctl >/dev/null 2>&1; then
    if systemctl is-active --quiet "$SERVICE_NAME" 2>/dev/null; then
        info "Stopping $SERVICE_NAME for upgrade..."
        systemctl stop "$SERVICE_NAME"
        SERVICE_WAS_RUNNING=true
    fi
fi

# ─── Install binary ─────────────────────────────────────────────────────────

info "Installing binary to $BIN_DIR/$BINARY_NAME..."
install -m 755 "$EXTRACTED_BIN" "$BIN_DIR/$BINARY_NAME"
ok "Binary installed"

# Verify
INSTALLED_VERSION=$("$BIN_DIR/$BINARY_NAME" version 2>/dev/null | head -1 | awk '{print $NF}' || echo "$VERSION")

# ─── Create directories ─────────────────────────────────────────────────────

mkdir -p "$CONFIG_DIR" && chmod 755 "$CONFIG_DIR"
mkdir -p "$DATA_DIR" && chmod 700 "$DATA_DIR"
ok "Directories created"

# ─── Config template ────────────────────────────────────────────────────────

if [ ! -f "$CONFIG_DIR/config.yaml.example" ]; then
    cat > "$CONFIG_DIR/config.yaml.example" << 'CONFIGEOF'
# ETC Collector Configuration
# ───────────────────────────
# Copy this file to config.yaml and customize:
#   sudo cp config.yaml.example config.yaml
#   sudo nano config.yaml
#
# Environment variables also work:
#   LDAP_URL, LDAP_BIND_DN, LDAP_BIND_PASSWORD, LDAP_BASE_DN
#   AZURE_TENANT_ID, AZURE_CLIENT_ID, AZURE_CLIENT_SECRET
#   PORT, LOG_LEVEL

server:
  host: "0.0.0.0"
  port: 8443

# Active Directory (LDAP)
ldap:
  # url: "ldaps://dc.example.com:636"
  # bindDN: "CN=svc-audit,CN=Users,DC=example,DC=com"
  # bindPassword: "${LDAP_BIND_PASSWORD}"
  # baseDN: "DC=example,DC=com"
  tlsVerify: true
  timeout: 30s
  pageSize: 1000

# Azure Entra ID
# azure:
#   tenantId: "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
#   clientId: "yyyyyyyy-yyyy-yyyy-yyyy-yyyyyyyyyyyy"
#   clientSecret: "${AZURE_CLIENT_SECRET}"

# JWT Authentication (auto-generated if missing)
auth:
  jwtPrivateKeyPath: "/etc/etc-collector/keys/private.pem"
  jwtPublicKeyPath: "/etc/etc-collector/keys/public.pem"
  tokenLifetime: 720h   # 30 days

# Logging
log:
  level: "info"        # debug, info, warn, error
  format: "console"    # console, json

# Optional features
features:
  networkProbes: false  # DNS AXFR, ADCS HTTP probes
CONFIGEOF
    ok "Config template created at $CONFIG_DIR/config.yaml.example"
else
    info "Config template already exists, skipping"
fi

# ─── Systemd service ────────────────────────────────────────────────────────

if [ "$NO_SERVICE" = false ]; then
    cat > "$SERVICE_DIR/$SERVICE_FILE" << UNITEOF
[Unit]
Description=ETC Collector - Identity Security Audit
Documentation=https://github.com/etcsec-com/etc-collector
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=$BIN_DIR/$BINARY_NAME server
Restart=always
RestartSec=10
User=root
WorkingDirectory=$DATA_DIR

# Hardening
NoNewPrivileges=yes
ProtectSystem=strict
ReadWritePaths=$CONFIG_DIR $DATA_DIR
PrivateTmp=yes

[Install]
WantedBy=multi-user.target
UNITEOF

    systemctl daemon-reload
    systemctl enable "$SERVICE_NAME" >/dev/null 2>&1
    ok "Service installed and enabled"

    # Restart if it was running before upgrade
    if [ "$SERVICE_WAS_RUNNING" = true ]; then
        info "Restarting $SERVICE_NAME..."
        systemctl start "$SERVICE_NAME"
        ok "Service restarted"
    fi
fi

# ─── Summary ────────────────────────────────────────────────────────────────

printf "\n"
printf "  ${GREEN}${BOLD}ETC Collector v${INSTALLED_VERSION} installed successfully!${NC}\n"
printf "\n"
printf "  Binary:   ${BOLD}$BIN_DIR/$BINARY_NAME${NC}\n"
printf "  Config:   $CONFIG_DIR/\n"
printf "  Data:     $DATA_DIR/\n"

if [ "$NO_SERVICE" = false ]; then
    if [ "$SERVICE_WAS_RUNNING" = true ]; then
        printf "  Service:  $SERVICE_NAME (running)\n"
    else
        printf "  Service:  $SERVICE_NAME (enabled, not started)\n"
    fi
fi

if [ "$UPGRADING" = true ]; then
    printf "\n  ${CYAN}Upgraded: $CURRENT_VERSION -> $INSTALLED_VERSION${NC}\n"
fi

# Show next steps only for fresh installs (not upgrades with running service)
if [ "$SERVICE_WAS_RUNNING" = false ]; then
    printf "\n"
    printf "  ${BOLD}Next steps:${NC}\n"
    printf "    1. Configure:  sudo cp $CONFIG_DIR/config.yaml.example $CONFIG_DIR/config.yaml\n"
    printf "                   sudo nano $CONFIG_DIR/config.yaml\n"
    printf "    2. Start:      sudo systemctl start $SERVICE_NAME\n"
    printf "    3. Status:     sudo systemctl status $SERVICE_NAME\n"
    printf "    4. Logs:       sudo journalctl -u $SERVICE_NAME -f\n"
fi

printf "\n"
