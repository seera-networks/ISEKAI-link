#!/usr/bin/env bash
#
# Build isekai-client-ffi for iOS and assemble the two things the Xcode project
# consumes:
#
#   IsekaiCameraClient/Generated/isekai_client_ffi.swift    UniFFI bindings
#   IsekaiCameraClient/Frameworks/IsekaiClientFFI.xcframework
#
# Both are generated, not committed. Run this before `xcodegen generate`, and
# again whenever the FFI crate's API changes.
#
# Requires a macOS host with Xcode, plus:
#   rustup target add aarch64-apple-ios aarch64-apple-ios-sim
#
# Usage: ./build-rust.sh [--release] [--sim-only]
set -euo pipefail

PROFILE=debug
SIM_ONLY=0

while [ $# -gt 0 ]; do
    case "$1" in
        --release) PROFILE=release ;;
        --sim-only) SIM_ONLY=1 ;;
        -h|--help) sed -n '2,15p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
        *) echo "unknown option: $1" >&2; exit 2 ;;
    esac
    shift
done

IOS_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
RUST_DIR=$(cd "$IOS_DIR/../rust" && pwd)
TARGET_DIR="$RUST_DIR/target"
APP_DIR="$IOS_DIR/IsekaiCameraClient"
GENERATED_DIR="$APP_DIR/Generated"
FRAMEWORKS_DIR="$APP_DIR/Frameworks"
STAGE_DIR="$TARGET_DIR/ios-stage"

CARGO_FLAGS=(-p isekai-client-ffi --manifest-path "$RUST_DIR/Cargo.toml")
if [ "$PROFILE" = release ]; then
    CARGO_FLAGS+=(--release)
fi

SIM_TRIPLE=aarch64-apple-ios-sim
DEVICE_TRIPLE=aarch64-apple-ios
if [ "$SIM_ONLY" = 1 ]; then
    TRIPLES=("$SIM_TRIPLE")
else
    TRIPLES=("$SIM_TRIPLE" "$DEVICE_TRIPLE")
fi

# Both are wholly generated; clearing them keeps a renamed binding file from
# lingering and being compiled alongside its replacement.
rm -rf "$STAGE_DIR" "$GENERATED_DIR"
mkdir -p "$STAGE_DIR/headers" "$GENERATED_DIR" "$FRAMEWORKS_DIR"

# --- Swift bindings -----------------------------------------------------------
#
# uniffi-bindgen reads the crate's exported metadata out of a built library. The
# host build is the cheapest one to point it at — it is needed anyway to produce
# the uniffi-bindgen binary itself.
echo "==> building isekai-client-ffi for the host"
cargo build "${CARGO_FLAGS[@]}"

echo "==> generating Swift bindings"
"$TARGET_DIR/$PROFILE/uniffi-bindgen" generate \
    --library "$TARGET_DIR/$PROFILE/libisekai_client_ffi.dylib" \
    --language swift \
    --out-dir "$STAGE_DIR/bindings"

# The .swift goes into the app target; the header and its modulemap describe the
# static library and travel inside the xcframework.
cp "$STAGE_DIR/bindings/"*.swift "$GENERATED_DIR/"
cp "$STAGE_DIR/bindings/"*.h "$STAGE_DIR/headers/"
# XCFramework header directories must name the modulemap `module.modulemap`.
cp "$STAGE_DIR/bindings/"*.modulemap "$STAGE_DIR/headers/module.modulemap"

# --- Static library slices ----------------------------------------------------
#
# msquic is linked with `-bundle`, so rustc leaves libmsquic.a out of the Rust
# staticlib and expects the final linker to supply it. Xcode links the
# xcframework and nothing else, so fold the two archives together here.
#
# A target directory can hold several seera-msquic-<hash>/out trees left over
# from earlier dependency resolutions; take the most recently written one.
find_msquic() {
    local newest="" candidate
    while IFS= read -r candidate; do
        if [ -z "$newest" ] || [ "$candidate" -nt "$newest" ]; then
            newest=$candidate
        fi
    done < <(find "$TARGET_DIR/$1/$PROFILE/build" -path '*/out/lib/libmsquic.a' -type f 2>/dev/null)
    printf '%s' "$newest"
}

XCFRAMEWORK_ARGS=()
for triple in "${TRIPLES[@]}"; do
    echo "==> building isekai-client-ffi for $triple"
    cargo build "${CARGO_FLAGS[@]}" --target "$triple"

    rust_lib="$TARGET_DIR/$triple/$PROFILE/libisekai_client_ffi.a"
    msquic_lib=$(find_msquic "$triple")
    if [ -z "$msquic_lib" ]; then
        echo "libmsquic.a not found for $triple under $TARGET_DIR/$triple/$PROFILE/build" >&2
        exit 1
    fi

    slice_dir="$STAGE_DIR/$triple"
    mkdir -p "$slice_dir"
    libtool -static -no_warning_for_no_symbols \
        -o "$slice_dir/libIsekaiClientFFI.a" "$rust_lib" "$msquic_lib"

    XCFRAMEWORK_ARGS+=(-library "$slice_dir/libIsekaiClientFFI.a" -headers "$STAGE_DIR/headers")
done

# --- XCFramework --------------------------------------------------------------
echo "==> assembling IsekaiClientFFI.xcframework"
rm -rf "$FRAMEWORKS_DIR/IsekaiClientFFI.xcframework"
xcodebuild -create-xcframework \
    "${XCFRAMEWORK_ARGS[@]}" \
    -output "$FRAMEWORKS_DIR/IsekaiClientFFI.xcframework"

echo
echo "bindings:    $GENERATED_DIR"
echo "xcframework: $FRAMEWORKS_DIR/IsekaiClientFFI.xcframework"
