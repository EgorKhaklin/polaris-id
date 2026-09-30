#!/bin/bash
# =============================================================================
#  Polaris.command — double-click launcher
#
#  WHAT IT DOES
#    1. Strips macOS quarantine attributes from the bundle so subsequent
#       Terminal launches don't trip Gatekeeper warnings.
#    2. Resolves its own folder (so it works no matter where the bundle lives).
#    3. Hands off to polaris_mac_launch.sh in `up` mode, which:
#         - Auto-starts Docker Desktop if installed but not running
#         - Self-heals stale-volume password drift
#         - Brings up Postgres + Flask, opens the browser, watches for tab close
#
#  WHY THIS FILE EXISTS
#    Finder opens *.command files with Terminal on double-click. macOS will
#    NOT open *.sh files this way without manual configuration. The .command
#    extension is the macOS equivalent of an executable for shell-based apps.
#
#  GATEKEEPER FIRST-RUN
#    The very first time you double-click after extracting from a downloaded
#    zip, macOS will say "Apple cannot check it for malicious software" and
#    refuse to run. Right-click the file → Open → Open. After that one
#    permission, it works on all subsequent double-clicks AND we strip the
#    quarantine bits below so even bash-from-terminal launches stop nagging.
# =============================================================================

set +e

# Resolve the directory this file lives in. Works whether the bundle was
# extracted to ~/Desktop, ~/Downloads, ~/Documents, or anywhere else.
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd)"
cd "$HERE" || exit 1

# Self-heal: strip quarantine attributes from the entire bundle. Once the user
# has clicked through Gatekeeper once, this prevents the warning from coming
# back on subsequent launches and lets the inner shell scripts run cleanly.
xattr -cr "$HERE" 2>/dev/null

# Make sure the executable bits survive zip extraction quirks.
chmod +x ./polaris_mac_launch.sh 2>/dev/null
chmod +x ./Polaris.command 2>/dev/null
[ -f ./polaris_web/docker-init.sh ] && chmod +x ./polaris_web/docker-init.sh 2>/dev/null
[ -f ./polaris_web/setup.sh ]       && chmod +x ./polaris_web/setup.sh       2>/dev/null

clear

# Clean ASCII banner — no emojis, intelligence-report aesthetic
cat <<'EOF'

╔══════════════════════════════════════════════════════════════╗
║                                                              ║
║                   P  O  L  A  R  I  S                        ║
║                                                              ║
║                  Identity Token System                       ║
║                  Fixus inter mutabilia                       ║
║                                                              ║
╚══════════════════════════════════════════════════════════════╝

EOF

echo "  Bundle:  $HERE"
echo "  Date:    $(date '+%Y-%m-%d %H:%M:%S %Z')"
echo
echo "  Bringing up the stack. The browser will open when ready."
echo "  Close the browser tab to shut down (or press Ctrl+C here)."
echo
echo "──────────────────────────────────────────────────────────────"
echo

./polaris_mac_launch.sh up
LAUNCH_EXIT=$?

echo
echo "──────────────────────────────────────────────────────────────"
if [ $LAUNCH_EXIT -eq 0 ]; then
    echo "  Polaris has stopped cleanly."
else
    echo "  Polaris exited with status $LAUNCH_EXIT."
    echo
    echo "  If something looks broken, try:"
    echo "    Open Terminal in this folder and run:"
    echo "      ./polaris_mac_launch.sh doctor    # diagnostic"
    echo "      ./polaris_mac_launch.sh nuke      # full reset"
    echo "      ./polaris_mac_launch.sh up        # bring it back up"
fi
echo
echo "  Press Return to close this window."
read -r _ || true
