#!/bin/sh
# Launches camera-server headless: signs in from the persisted Auth0 session,
# opens the P2P listener, and starts capture automatically (CAMERA_AUTOSTART /
# P2P_AUTOSTART), with no GUI interaction. Meant to be run under a virtual
# display (e.g. Xvfb) by a systemd service or equivalent supervisor.
set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
cd "$SCRIPT_DIR"

# The seera-msquic build output directory's hash changes across rebuilds, so
# it can't be hardcoded -- resolve whichever one is actually on disk each
# time this starts.
MSQUIC_LIB_DIR=$(find target/debug/build/seera-msquic-*/out/lib/libmsquic.so.2 \
    -printf '%h\n' 2>/dev/null | head -1)
if [ -z "$MSQUIC_LIB_DIR" ]; then
    echo "run-camera-server.sh: no libmsquic.so.2 found under target/debug/build/seera-msquic-*/out/lib -- has camera-server been built?" >&2
    exit 1
fi

: "${OPENCV_LIB_DIR:?set OPENCV_LIB_DIR to your local OpenCV build's lib dir, e.g. \$HOME/opencv-4.12-local/lib}"
: "${DISPLAY:=:99}"

export DISPLAY
export LD_LIBRARY_PATH="$MSQUIC_LIB_DIR:$OPENCV_LIB_DIR${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
export RUST_LOG="${RUST_LOG:-camera_core=debug,isekai_p2p_core=debug,camera_server=debug}"
export CAMERA_AUTOSTART=1
export P2P_AUTOSTART=1
exec ./target/debug/camera-server
