#!/usr/bin/env sh
# Credits (∀ / XCR) — Zero-Dependency SHA-256 Verified Binary Installer (Linux & macOS)
# Usage: curl -fsSL https://raw.githubusercontent.com/haruki-morimoto/credit/main/scripts/install.sh | sh
set -eu

REPO="haruki-morimoto/credit"
TAG="${XCR_VERSION:-v0.3.0-testnet}"
INSTALL_DIR="${XCR_INSTALL_DIR:-$HOME/.local/bin}"

OS="$(uname -s)"
ARCH="$(uname -m)"

case "${OS}-${ARCH}" in
  Linux-x86_64|Linux-amd64)
    TARGET_LABEL="linux-x86_64"
    ;;
  Darwin-arm64|Darwin-aarch64)
    TARGET_LABEL="macos-arm64"
    ;;
  Darwin-x86_64)
    TARGET_LABEL="macos-x86_64"
    ;;
  *)
    echo "error: unsupported platform ${OS}-${ARCH} (build from source with: cargo build --release)" >&2
    exit 1
    ;;
esac

STAGE="credits-${TAG}-${TARGET_LABEL}"
ARCHIVE="${STAGE}.tar.gz"
BASE_URL="https://github.com/${REPO}/releases/download/${TAG}"

TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

echo "==> Downloading ${ARCHIVE} and SHA-256 checksum from GitHub Releases..."
curl -fsSL "${BASE_URL}/${ARCHIVE}" -o "${TMP_DIR}/${ARCHIVE}"
curl -fsSL "${BASE_URL}/${ARCHIVE}.sha256" -o "${TMP_DIR}/${ARCHIVE}.sha256"

echo "==> Verifying cryptographic SHA-256 checksum..."
(
  cd "$TMP_DIR"
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum -c "${ARCHIVE}.sha256"
  elif command -v shasum >/dev/null 2>&1; then
    shasum -a 256 -c "${ARCHIVE}.sha256"
  else
    echo "error: neither sha256sum nor shasum found to verify release archive" >&2
    exit 1
  fi
)

mkdir -p "$INSTALL_DIR"
tar -xzf "${TMP_DIR}/${ARCHIVE}" -C "$TMP_DIR"
for bin in credit-node credit-cli credit-gateway; do
  install -m 0755 "${TMP_DIR}/${STAGE}/${bin}" "${INSTALL_DIR}/${bin}"
done

echo ""
echo "=========================================================================="
echo "  Credits (∀ / XCR) ${TAG} installed to ${INSTALL_DIR}"
echo "=========================================================================="
echo "  1. Ensure ${INSTALL_DIR} is on your PATH:"
echo "     export PATH=\"${INSTALL_DIR}:\$PATH\""
echo ""
echo "  2. Join the Live Global Public Testnet (earns solo PoNC rewards every 60s):"
echo "     credit-node peer --testnet --bind 0.0.0.0:9501 --data-dir ./my-testnet-node"
echo ""
echo "  3. Pre-join the 2027-01-01T00:00:00Z Mainnet Live Standby Mesh:"
echo "     credit-node peer --mainnet --bind 0.0.0.0:9500 --data-dir ./my-mainnet-node"
echo "=========================================================================="
