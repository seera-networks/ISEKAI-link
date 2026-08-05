#!/usr/bin/env bash
#
# Package the camera apps with the libraries they need to run somewhere else.
#
#   scripts/bundle-camera-apps.sh <release-dir> <output-dir> <bundle-name>
#
# The problem this solves: `camera-server` and `camera-client` link against
# OpenCV 4.11+, which no current Ubuntu packages, and against `libmsquic.so`,
# which exists only inside cargo's build-script output directory. A binary on
# its own runs on the machine that built it and nowhere else.
#
# So the same thing the server's Dockerfile does for its release tarball: walk
# the dynamic dependencies, copy them in beside the binaries, and put a launcher
# in front that points the loader at them.
#
#   <bundle-name>/
#   ├── camera-server      launcher
#   ├── camera-client      launcher
#   ├── bin/               the binaries
#   └── lib/               libmsquic, OpenCV, and what those pull in
#
# **Two families are deliberately left out.** The C runtime, because mixing a
# bundled glibc with the host's loader is what breaks tarballs like this one.
# And the graphics, display and input stack — GL, X11, Wayland, DRM, udev —
# because those have to match the drivers and session actually running on the
# machine, and a bundled copy is how a window ends up never appearing.
set -euo pipefail

release_dir=${1:?usage: bundle-camera-apps.sh <release-dir> <output-dir> <bundle-name>}
out_dir=${2:?usage: bundle-camera-apps.sh <release-dir> <output-dir> <bundle-name>}
name=${3:?usage: bundle-camera-apps.sh <release-dir> <output-dir> <bundle-name>}

apps=(camera-server camera-client)
stage="${out_dir}/${name}"
rm -rf "${stage}"
mkdir -p "${stage}/bin" "${stage}/lib"

for app in "${apps[@]}"; do
    cp -a "${release_dir}/${app}" "${stage}/bin/"
done

# libmsquic is built by seera-msquic's build script and never installed, so it
# is found by searching cargo's output rather than at a fixed path — CMake's
# GNUInstallDirs puts it under `lib` or `lib64` depending on the distribution.
find_msquic() {
    local pattern=$1
    find "${release_dir}/build" -path '*/out/*' -name "${pattern}" -print 2>/dev/null | head -1
}

case "$(uname -s)" in
# --------------------------------------------------------------------- Linux
Linux)
    msquic=$(find_msquic 'libmsquic.so')
    [ -n "${msquic}" ] || { echo "libmsquic.so not found under ${release_dir}/build" >&2; exit 1; }
    cp -a "$(dirname "${msquic}")"/libmsquic.so* "${stage}/lib/"

    # Names, not paths: the same library appears under different prefixes on
    # different distributions.
    is_host_library() {
        case "$1" in
            libc.so.*|libm.so.*|libdl.so.*|librt.so.*|libpthread.so.*|libresolv.so.*) return 0;;
            libgcc_s.so.*|ld-linux*|libstdc++.so.*) return 0;;
            libGL*|libEGL*|libGLX*|libGLdispatch*|libOpenGL*|libgbm*|libdrm*) return 0;;
            libX*|libxcb*|libwayland-*|libxkbcommon*) return 0;;
            libudev.so.*|libsystemd.so.*) return 0;;
        esac
        return 1
    }

    for app in "${apps[@]}"; do
        LD_LIBRARY_PATH="${stage}/lib" ldd "${stage}/bin/${app}" \
            | awk '/=> \//{print $3}' \
            | while read -r so; do
                base=$(basename "${so}")
                if is_host_library "${base}"; then
                    continue
                fi
                [ -e "${stage}/lib/${base}" ] || cp -aL "${so}" "${stage}/lib/"
              done
    done

    for app in "${apps[@]}"; do
        cat > "${stage}/${app}" <<LAUNCHER
#!/bin/sh
# Run ${app} against the libraries shipped in this bundle.
here="\$(cd "\$(dirname "\$0")" && pwd)"
exec env LD_LIBRARY_PATH="\${here}/lib\${LD_LIBRARY_PATH:+:\${LD_LIBRARY_PATH}}" \\
    "\${here}/bin/${app}" "\$@"
LAUNCHER
        chmod 0755 "${stage}/${app}"
    done
    ;;

# --------------------------------------------------------------------- macOS
Darwin)
    msquic=$(find_msquic 'libmsquic.dylib')
    [ -n "${msquic}" ] || { echo "libmsquic.dylib not found under ${release_dir}/build" >&2; exit 1; }
    cp -a "$(dirname "${msquic}")"/libmsquic*.dylib "${stage}/lib/"

    # No launcher here, and no `DYLD_LIBRARY_PATH`: System Integrity Protection
    # strips `DYLD_*` from the environment when a protected binary is executed,
    # and `/bin/sh` is protected — so a launcher script would have the variable
    # removed before it ever reached the app. The load commands are rewritten
    # instead, which is what macOS expects of a relocatable bundle anyway.
    is_host_library() {
        case "$1" in
            /usr/lib/*|/System/*) return 0;;
        esac
        return 1
    }

    # Dependencies pull in dependencies — Homebrew's OpenCV on ffmpeg on a dozen
    # codecs — so this walks until nothing new turns up.
    pending=()
    for app in "${apps[@]}"; do
        pending+=("${stage}/bin/${app}")
    done
    while [ ${#pending[@]} -gt 0 ]; do
        current=${pending[0]}
        pending=("${pending[@]:1}")
        # Skip the first line, which is the file's own install name.
        while read -r dep; do
            if is_host_library "${dep}"; then
                continue
            fi
            base=$(basename "${dep}")
            if [ ! -e "${stage}/lib/${base}" ]; then
                cp -L "${dep}" "${stage}/lib/${base}"
                chmod u+w "${stage}/lib/${base}"
                install_name_tool -id "@rpath/${base}" "${stage}/lib/${base}"
                pending+=("${stage}/lib/${base}")
            fi
            install_name_tool -change "${dep}" "@rpath/${base}" "${current}" 2>/dev/null || true
          done < <(otool -L "${current}" | tail -n +2 | awk '{print $1}')
    done

    for app in "${apps[@]}"; do
        # `@executable_path` is the binary's own directory, so this resolves to
        # the bundle's lib/ wherever the bundle is unpacked.
        install_name_tool -add_rpath "@executable_path/../lib" "${stage}/bin/${app}" 2>/dev/null || true
        # A one-line launcher only so the bundle is started the same way on both
        # platforms; nothing has to be set for it to work.
        cat > "${stage}/${app}" <<LAUNCHER
#!/bin/sh
here="\$(cd "\$(dirname "\$0")" && pwd)"
exec "\${here}/bin/${app}" "\$@"
LAUNCHER
        chmod 0755 "${stage}/${app}"
    done
    ;;

*)
    echo "unsupported platform: $(uname -s) — Windows is packaged in the workflow" >&2
    exit 1
    ;;
esac

echo "bundled into ${stage}:"
ls -l "${stage}" "${stage}/bin"
echo "libraries: $(find "${stage}/lib" -type f | wc -l)"
