#!/bin/sh
# Launches camera-server headless: picks up a previously-restored Auth0
# sign-in (with_stored_auth0 reads the token file and builds the refresher;
# it makes no network call itself -- the first call using it is whatever
# needs a token next, which is not this script) and starts capture
# automatically (CAMERA_AUTOSTART), with no GUI interaction needed for
# either. It does NOT open the P2P listener automatically -- that still
# needs a human to click "Open" at least once.
#
# That is deliberate, not a missing feature: an earlier version of this
# script set P2P_AUTOSTART=1 too, which opened P2P (and, combined with
# CAMERA_AUTOSTART, started publishing to peers) before the privacy-consent
# gate (camera_ui::ConsentGate) had ever been shown to anyone -- see PR #151's
# review for the full reasoning. Requiring a human to click Open is what
# keeps consent genuinely interactive rather than bypassed; CAMERA_AUTOSTART
# alone never touches the network, so it doesn't have that problem.
#
# Meant to be run under a virtual display (e.g. Xvfb) by a systemd service or
# equivalent supervisor -- see camera-server.service alongside this script,
# which provides the display via xvfb-run rather than this script managing
# one itself.
set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
# This script lives in scripts/; the cargo workspace (and the build output
# below) is a sibling directory, not this one.
cd "$SCRIPT_DIR/../rust"

PROFILE="${PROFILE:-debug}"

# The seera-msquic build output directory's hash changes across rebuilds, and
# a stale one from an earlier build can still be on disk -- nothing removes
# it short of `cargo clean` -- so this doesn't just take the first match, it
# picks the most recently built one. Matched by name only, not a hardcoded
# subdirectory: CMake's GNUInstallDirs puts the library under `lib` or
# `lib64` depending on the distribution, and on at least one real machine it
# was under `out/artifacts` instead of either (confirmed in review) -- same
# reasoning as scripts/bundle-apps.sh's own find_msquic, which searches this
# broadly for the same reason, not a `lib`-vs-`lib64` split specifically.
MSQUIC_LIB_DIR=$(find "target/$PROFILE/build/seera-msquic-"*/out -name 'libmsquic.so*' \
    -printf '%T@ %h\n' 2>/dev/null | sort -rn | head -1 | cut -d' ' -f2-)
if [ -z "$MSQUIC_LIB_DIR" ]; then
    echo "run-camera-server.sh: no libmsquic.so found under target/$PROFILE/build/seera-msquic-*/out -- has camera-server been built?" >&2
    exit 1
fi

: "${OPENCV_LIB_DIR:?set OPENCV_LIB_DIR to your local OpenCV build's lib dir, e.g. \$HOME/opencv-4.12-local/lib}"
# A convenience default matching camera-server.service's own display number,
# for running this by hand against an already-running Xvfb -- not load-bearing
# when this runs under that unit, since xvfb-run sets DISPLAY itself.
: "${DISPLAY:=:99}"

export DISPLAY
export LD_LIBRARY_PATH="$MSQUIC_LIB_DIR:$OPENCV_LIB_DIR${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
export RUST_LOG="${RUST_LOG:-camera_core=debug,isekai_p2p_core=debug,camera_server=debug}"
export CAMERA_AUTOSTART=1
exec "./target/$PROFILE/camera-server"
