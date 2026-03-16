#!/bin/bash
set -e

REPO="https://github.com/jackgladowsky/mcp-certify.git"
INSTALL_DIR="$HOME/.mcp-certify"
BIN_LINK="/usr/local/bin/mcp-certify"

# Check node version
NODE_VERSION=$(node -v 2>/dev/null | sed 's/v//' | cut -d. -f1)
if [ -z "$NODE_VERSION" ] || [ "$NODE_VERSION" -lt 20 ]; then
  echo "Error: Node.js 20+ is required (got $(node -v 2>/dev/null || echo 'none'))"
  exit 1
fi

echo "Installing mcp-certify..."

# Clone or update
if [ -d "$INSTALL_DIR" ]; then
  echo "Updating existing installation..."
  cd "$INSTALL_DIR"
  git pull --quiet
else
  git clone --quiet --depth 1 "$REPO" "$INSTALL_DIR"
  cd "$INSTALL_DIR"
fi

# Install deps and build
npm install --silent 2>/dev/null
npm run build --silent 2>/dev/null
chmod +x dist/cli.js

# Symlink
if [ -w "$(dirname "$BIN_LINK")" ]; then
  ln -sf "$INSTALL_DIR/dist/cli.js" "$BIN_LINK"
else
  sudo ln -sf "$INSTALL_DIR/dist/cli.js" "$BIN_LINK"
fi

echo ""
echo "mcp-certify installed successfully!"
echo ""
echo "  mcp-certify doctor                    # check environment"
echo "  mcp-certify npx -y @modelcontextprotocol/server-filesystem /tmp"
echo ""
