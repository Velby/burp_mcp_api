#!/usr/bin/env bash
# Burp REST Bridge — setup script
# Installs the Python MCP server and registers it with Claude Code.
# Run from any directory: bash /path/to/setup.sh

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MCP_SCRIPT="$SCRIPT_DIR/burp_mcp.py"
CLIENT_SCRIPT="$SCRIPT_DIR/burp_client.py"

# ── colours ──────────────────────────────────────────────────────────────────
GREEN='\033[0;32m'; YELLOW='\033[1;33m'; RED='\033[0;31m'; NC='\033[0m'
ok()   { echo -e "${GREEN}✓${NC} $*"; }
warn() { echo -e "${YELLOW}!${NC} $*"; }
err()  { echo -e "${RED}✗${NC} $*"; }
h()    { echo -e "\n${YELLOW}=== $* ===${NC}"; }

# ── Python ───────────────────────────────────────────────────────────────────
h "Checking Python"
if command -v python3 &>/dev/null; then
    PYTHON=python3
elif command -v python &>/dev/null && python --version 2>&1 | grep -q "Python 3"; then
    PYTHON=python
else
    err "Python 3 not found. Install Python 3.8+ and re-run."
    exit 1
fi
ok "Using $($PYTHON --version)"

# ── Python dependencies ───────────────────────────────────────────────────────
h "Installing Python dependencies"
for pkg in fastmcp requests; do
    if $PYTHON -c "import $pkg" 2>/dev/null; then
        ok "$pkg already installed"
    else
        # Try normal install first; fall back to --user on systems with PEP 668 (Debian/Ubuntu)
        if $PYTHON -m pip install "$pkg" --quiet 2>/dev/null; then
            ok "$pkg installed"
        elif $PYTHON -m pip install "$pkg" --user --quiet 2>/dev/null; then
            ok "$pkg installed (--user)"
        else
            err "Could not install $pkg automatically. Run one of:"
            echo "    $PYTHON -m pip install $pkg --user"
            echo "    pipx install $pkg"
            exit 1
        fi
    fi
done

# ── quick smoke test ──────────────────────────────────────────────────────────
h "Verifying MCP server loads"
if $PYTHON -c "import sys; sys.path.insert(0, '$SCRIPT_DIR'); import fastmcp; import requests; import burp_client" 2>/dev/null; then
    ok "burp_mcp.py dependencies look good"
else
    warn "Import check failed — make sure burp_client.py is in the same directory as burp_mcp.py"
fi

# ── Claude Code MCP registration ─────────────────────────────────────────────
h "Registering MCP server with Claude Code"
MCP_CMD="$PYTHON $MCP_SCRIPT"
if command -v claude &>/dev/null; then
    # Remove old registration if it exists, ignore errors
    claude mcp remove burp 2>/dev/null || true
    # -s user = available in ALL projects, not just this directory
    claude mcp add -s user burp -- $PYTHON "$MCP_SCRIPT"
    ok "Registered as 'burp' (user scope) — Claude now has Burp tools in every project"
else
    warn "'claude' CLI not found — register manually once it's installed:"
    echo "    claude mcp add -s user burp -- $PYTHON $MCP_SCRIPT"
fi

# ── JAR location ─────────────────────────────────────────────────────────────
h "Burp extension JAR"
JAR="$SCRIPT_DIR/extension/build/libs/burp-rest-bridge.jar"
if [ -f "$JAR" ]; then
    ok "JAR found at:"
    echo "    $JAR"
else
    warn "Pre-built JAR not found. Build it with:"
    echo "    cd $SCRIPT_DIR/extension"
    echo "    ./gradlew jar   # set JAVA_HOME if needed, e.g. JAVA_HOME=/path/to/jdk ./gradlew jar"
    echo ""
    echo "  Or download a release JAR and place it alongside this script."
    JAR="$SCRIPT_DIR/burp-rest-bridge.jar"
fi

# ── Final instructions ────────────────────────────────────────────────────────
h "Load the extension in Burp Suite"
echo "  This is a manual step — do it once per Burp installation:"
echo ""
echo "  1. Open Burp Suite"
echo "  2. Go to the Extensions tab (top menu bar)"
echo "  3. Click 'Add' (top-left of the Installed Extensions table)"
echo "  4. Set Extension type to: Java"
echo "  5. Click 'Select file' and choose:"
echo "         $JAR"
echo "  6. Click Next — you should see 'Burp REST Bridge' appear in the extensions list"
echo "     with 'Loaded' checked and no errors in the Output tab"
echo ""
echo "  The extension immediately starts a REST API on http://127.0.0.1:8090"
echo "  and backfills your existing proxy history."
echo ""
echo "  To reload after a JAR rebuild: hold Ctrl (or Cmd on Mac) and click"
echo "  the 'Loaded' checkbox next to the extension — faster than re-adding it."

h "Test the connection"
echo "  With Burp running and the extension loaded, run:"
echo ""
echo "      $PYTHON $CLIENT_SCRIPT health"
echo ""
echo "  Expected output: {\"status\": \"ok\", \"count\": <N>, \"port\": 8090}"
echo ""
echo "  Or just ask Claude: 'Is Burp running?' and it will call burp_health() directly."

h "Done — Claude tools available in every project"
echo "    burp_health          check the extension is running"
echo "    burp_hosts           list all captured hostnames"
echo "    burp_search          search proxy history (host, method, status, text, ...)"
echo "    burp_get_item        fetch full request + response for one item"
echo "    burp_repeater_latest get the last request sent from Repeater"
echo "    burp_send_to_repeater send a captured request to a Repeater tab"
echo "    burp_scope           check if a URL is in Burp's target scope"
echo ""
