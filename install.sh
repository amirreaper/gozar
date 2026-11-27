#!/usr/bin/env bash
# Install the engines this tool needs (sing-box only).
# Usage:  bash install.sh
set -euo pipefail

ENGINE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/engines"
mkdir -p "$ENGINE_DIR"

have() { command -v "$1" >/dev/null 2>&1; }

echo "==> Detecting CPU architecture..."
OS="$(uname -s | tr '[:upper:]' '[:lower:]')"
ARCH_RAW="$(uname -m)"
case "$ARCH_RAW" in
  x86_64|amd64) ARCH="amd64" ;;
  aarch64|arm64) ARCH="arm64" ;;
  armv7l) ARCH="armv7" ;;
  *) echo "Unsupported architecture: $ARCH_RAW"; exit 1 ;;
esac
echo "    OS=$OS  ARCH=$ARCH"

# ─────────────────────────── sing-box ───────────────────────────
install_singbox() {
  if [ -x "$ENGINE_DIR/sing-box" ]; then
    echo "==> sing-box already present: $("$ENGINE_DIR/sing-box" version | head -1)"
    return
  fi
  if have sing-box; then
    ln -sf "$(command -v sing-box)" "$ENGINE_DIR/sing-box"
    echo "==> Using the sing-box already installed on this system."
    return
  fi
  echo "==> Downloading the latest sing-box..."
  TAG="$(curl -fsSL https://api.github.com/repos/SagerNet/sing-box/releases/latest | grep -oP '"tag_name":\s*"\K[^"]+')"
  VER="${TAG#v}"
  URL="https://github.com/SagerNet/sing-box/releases/download/${TAG}/sing-box-${VER}-${OS}-${ARCH}.tar.gz"
  echo "    $URL"
  TMP="$(mktemp -d)"
  curl -fL --retry 3 -o "$TMP/sb.tar.gz" "$URL"
  tar -xzf "$TMP/sb.tar.gz" -C "$TMP"
  find "$TMP" -name sing-box -type f -exec cp {} "$ENGINE_DIR/sing-box" \;
  chmod +x "$ENGINE_DIR/sing-box"
  rm -rf "$TMP"
  echo "==> sing-box installed: $("$ENGINE_DIR/sing-box" version | head -1)"
}

# Only sing-box is installed. xray was dropped in v1.8.0 (34MB that nothing
# read), and the DPI/fragment layer that needed extra binaries is gone too.
