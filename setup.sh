#!/usr/bin/env bash
# Burp REST Bridge — one-shot setup
# Run from any directory: bash /path/to/setup.sh

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MCP_SCRIPT="$SCRIPT_DIR/burp_mcp.py"

GREEN='\033[0;32m'; YELLOW='\033[1;33m'; RED='\033[0;31m'; NC='\033[0m'
ok()  { echo -e "${GREEN}✓${NC} $*"; }
warn(){ echo -e "${YELLOW}!${NC} $*"; }
err() { echo -e "${RED}✗${NC} $*"; }
h()   { echo -e "\n${YELLOW}=== $* ===${NC}"; }

# ── Python ────────────────────────────────────────────────────────────────────
h "Python"
if command -v python3 &>/dev/null; then
    PYTHON=python3
elif command -v python &>/dev/null && python --version 2>&1 | grep -q "Python 3"; then
    PYTHON=python
else
    err "Python 3 not found — install Python 3.8+ and re-run."; exit 1
fi
ok "$($PYTHON --version)"

# ── Build JAR ─────────────────────────────────────────────────────────────────
h "JAR"
JAR_SRC="$SCRIPT_DIR/extension/build/libs/burp-rest-bridge.jar"
JAR_LINK="$SCRIPT_DIR/burp-rest-bridge.jar"

# Find a JDK: system PATH first, then Burp's bundled JRE, then snap JBRs
if command -v javac &>/dev/null; then
    JAVA_HOME="$(java -XshowSettings:property -version 2>&1 \
        | grep 'java.home' | awk '{print $3}')"
else
    for candidate in \
        "$HOME/BurpSuitePro/jre" \
        "$HOME/BurpSuite/jre" \
        "/opt/BurpSuitePro/jre" \
        "/opt/BurpSuite/jre" \
        /snap/*/current/jbr; do
        if [ -x "$candidate/bin/javac" ]; then
            JAVA_HOME="$candidate"
            warn "System javac not found, using bundled JDK: $JAVA_HOME"
            break
        fi
    done
fi

if [ -z "$JAVA_HOME" ] || [ ! -x "$JAVA_HOME/bin/javac" ]; then
    err "No JDK found — install one and re-run, or build manually:"
    echo "    sudo apt install default-jdk"
    echo "    # or: JAVA_HOME=/snap/<app>/current/jbr bash setup.sh"; exit 1
fi

# Always let Gradle decide — it skips compilation when sources are unchanged (UP-TO-DATE)
if (cd "$SCRIPT_DIR/extension" && chmod +x gradlew && JAVA_HOME="$JAVA_HOME" ./gradlew jar --quiet); then
    ok "JAR up to date (JAVA_HOME=$JAVA_HOME)"
else
    err "Build failed — fix the error above then re-run, or build manually:"
    echo "    cd $SCRIPT_DIR/extension && JAVA_HOME=$JAVA_HOME ./gradlew jar"; exit 1
fi
ln -sf "$JAR_SRC" "$JAR_LINK"
ok "Symlink: $JAR_LINK"

# ── Python dependencies ───────────────────────────────────────────────────────
h "Python dependencies"
for pkg in fastmcp requests; do
    if $PYTHON -c "import $pkg" 2>/dev/null; then
        ok "$pkg already installed"
    elif $PYTHON -m pip install "$pkg" --quiet 2>/dev/null || \
         $PYTHON -m pip install "$pkg" --user --quiet 2>/dev/null; then
        ok "$pkg installed"
    else
        err "Could not install $pkg — run manually:"
        echo "    $PYTHON -m pip install $pkg --user"; exit 1
    fi
done

# ── API key ───────────────────────────────────────────────────────────────────
h "API key"
KEY_FILE="$HOME/.config/burp-rest-bridge/api_key"
mkdir -p "$(dirname "$KEY_FILE")"
if [ -f "$KEY_FILE" ]; then
    ok "Already exists: $KEY_FILE"
else
    $PYTHON -c "import secrets; print(secrets.token_hex(32))" > "$KEY_FILE"
    chmod 600 "$KEY_FILE"
    ok "Generated: $KEY_FILE"
fi

# ── MCP registration ──────────────────────────────────────────────────────────
h "MCP registration"
if command -v claude &>/dev/null; then
    claude mcp remove burp 2>/dev/null || true
    claude mcp add -s user burp -- $PYTHON "$MCP_SCRIPT"
    ok "Registered as 'burp' (user scope)"
else
    warn "'claude' CLI not found — register manually once installed:"
    echo "    claude mcp add -s user burp -- $PYTHON $MCP_SCRIPT"
fi

# Kill any running instance so the next Claude session picks up updated code
if pkill -f "python.*burp_mcp\.py" 2>/dev/null; then
    ok "Restarted MCP server (killed old process — will respawn on next use)"
fi

# ── Done ──────────────────────────────────────────────────────────────────────
h "All done"
echo ""
echo "  Load the extension in Burp Suite (one-time):"
echo "    Extensions → Add → Java → $JAR_LINK"
echo "    Ctrl+click 'Loaded' to hot-reload after a rebuild."
echo ""
echo "  Verify: $PYTHON $SCRIPT_DIR/burp_client.py health"
echo ""
