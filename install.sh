#!/bin/sh
set -eu

REPO="fengzdadi/codexgo"
VERSION="${CODEXGO_VERSION:-latest}"
INSTALL_DIR="${CODEXGO_INSTALL_DIR:-$HOME/.local/bin}"

os="$(uname -s)"
arch="$(uname -m)"

if [ "$os" != "Darwin" ]; then
  echo "CodexGo currently publishes macOS binaries only." >&2
  exit 1
fi

case "$arch" in
  arm64)
    asset="codexgo-darwin-arm64"
    ;;
  x86_64)
    asset="codexgo-darwin-amd64"
    ;;
  *)
    echo "Unsupported macOS architecture: $arch" >&2
    exit 1
    ;;
esac

if [ "$VERSION" = "latest" ]; then
  url="https://github.com/$REPO/releases/latest/download/$asset"
else
  url="https://github.com/$REPO/releases/download/$VERSION/$asset"
fi

tmp="${TMPDIR:-/tmp}/codexgo.$$"
cleanup() {
  rm -f "$tmp"
}
trap cleanup EXIT INT TERM

echo "Downloading CodexGo from $url"
curl -fsSL "$url" -o "$tmp"
chmod +x "$tmp"

mkdir -p "$INSTALL_DIR"
mv "$tmp" "$INSTALL_DIR/codexgo"
trap - EXIT INT TERM

echo "Installed CodexGo to $INSTALL_DIR/codexgo"

case ":$PATH:" in
  *":$INSTALL_DIR:"*)
    ;;
  *)
    echo
    echo "Add CodexGo to your PATH:"
    echo "  echo 'export PATH=\"\$HOME/.local/bin:\$PATH\"' >> ~/.zshrc"
    echo "  source ~/.zshrc"
    ;;
esac

echo
echo "Next steps:"
echo "  codexgo version"
echo "  codexgo init --scope user"
