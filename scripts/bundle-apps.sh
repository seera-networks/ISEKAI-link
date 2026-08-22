#!/usr/bin/env bash
#
# Package binaries with the libraries they need to run somewhere else.
#
#   scripts/bundle-apps.sh <release-dir> <output-dir> <bundle-name> <app>...
#
# The problem this solves: **every binary in this workspace links against
# `libmsquic`, which exists only inside cargo's build-script output directory**
# under a path with a build hash in it. Nothing installs it and nothing puts it
# on the loader's path, so `cargo run` works and the binary it built does not:
#
#   ./target/release/portal-server --help
#   error while loading shared libraries: libmsquic.so.2
#
# The camera apps add OpenCV 4.11+, which no current Ubuntu packages. Same
# answer either way, which is why this takes the app names rather than knowing
# them: walk the dynamic dependencies, copy them in beside the binaries, and put
# a launcher in front that points the loader at them.
#
# So the same thing the server's Dockerfile does for its release tarball: walk
# the dynamic dependencies, copy them in beside the binaries, and put a launcher
# in front that points the loader at them.
#
#   <bundle-name>/
#   ├── <app>              launcher, one per app
#   ├── bin/               the binaries
#   └── lib/               libmsquic and whatever else they pull in
#
# **Two families are deliberately left out.** The C runtime, because mixing a
# bundled glibc with the host's loader is what breaks tarballs like this one.
# And the graphics, display and input stack — GL, X11, Wayland, DRM, udev —
# because those have to match the drivers and session actually running on the
# machine, and a bundled copy is how a window ends up never appearing.
set -euo pipefail

usage='usage: bundle-apps.sh <release-dir> <output-dir> <bundle-name> <app>...'
release_dir=${1:?${usage}}
out_dir=${2:?${usage}}
name=${3:?${usage}}
shift 3
[ $# -gt 0 ] || { echo "${usage}" >&2; echo "name at least one app to bundle" >&2; exit 1; }
apps=("$@")
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

    # **Prepended, not assigned.** Replacing `LD_LIBRARY_PATH` hides exactly the
    # libraries this exists to collect: an OpenCV installed somewhere the loader
    # does not search by default — which is how CI installs it — then resolves
    # to "not found", and a walk that only reads resolved paths skips it in
    # silence. The bundle then builds, passes, and fails on the first machine
    # that is not the one that built it.
    search="${stage}/lib${LD_LIBRARY_PATH:+:${LD_LIBRARY_PATH}}"

    for app in "${apps[@]}"; do
        # A "not found" here is a library this machine does not have, so it
        # cannot be copied — and a silent skip is how the first bundle went out
        # without any ffmpeg. Said at the moment it happens; the check at the
        # end is what makes it fatal.
        LD_LIBRARY_PATH="${search}" ldd "${stage}/bin/${app}" \
            | awk '/not found/{print "warning: " $1 " is not installed here, so it \
cannot be bundled" > "/dev/stderr"} /=> \//{print $3}' \
            | while read -r so; do
                base=$(basename "${so}")
                if is_host_library "${base}"; then
                    continue
                fi
                [ -e "${stage}/lib/${base}" ] || cp -aL "${so}" "${stage}/lib/"
              done
    done

    # Copying a library can pull in another that the binary itself does not
    # name, so keep going until a pass adds nothing.
    while :; do
        before=$(find "${stage}/lib" -type f | wc -l)
        find "${stage}/lib" -name '*.so*' -type f -print0 \
            | while IFS= read -r -d '' lib; do
                LD_LIBRARY_PATH="${search}" ldd "${lib}" 2>/dev/null \
                    | awk '/not found/{print "warning: " $1 " is not installed here, so it \
cannot be bundled" > "/dev/stderr"} /=> \//{print $3}' \
                    | while read -r so; do
                        base=$(basename "${so}")
                        if is_host_library "${base}"; then
                            continue
                        fi
                        [ -e "${stage}/lib/${base}" ] || cp -aL "${so}" "${stage}/lib/"
                      done
              done
        [ "$(find "${stage}/lib" -type f | wc -l)" -eq "${before}" ] && break
    done

    # Symbols are most of what a Rust release binary weighs, and a bundle that
    # already carries a hundred libraries does not need them too. What is
    # stripped here is still in `target/release` on the machine that built it.
    strip --strip-all "${stage}"/bin/* 2>/dev/null || true
    # `--strip-unneeded` on the libraries: `--strip-all` on a shared object
    # removes the dynamic symbols it is loaded by.
    find "${stage}/lib" -type f -name '*.so*' -exec strip --strip-unneeded {} + 2>/dev/null || true

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

    # A dependency can be recorded as `@rpath/…`, `@loader_path/…` or
    # `@executable_path/…` rather than a path — resolving those means replaying
    # the referring binary's own rpaths, which is more machinery than this
    # needs. Skipped with a warning instead: the alternative, found the hard
    # way, is `cp: @rpath/libvtk….dylib: No such file or directory` taking the
    # whole job down over a library nothing here uses.
    is_unresolvable() {
        case "$1" in
            @*) return 0;;
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
            if is_unresolvable "${dep}"; then
                echo "warning: leaving ${dep} (referenced by ${current}) to the host" >&2
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
    done

    # `-x` keeps the globally visible symbols, which a dylib is loaded by;
    # anything stronger makes the bundle unloadable rather than smaller.
    strip -x "${stage}"/bin/* "${stage}"/lib/*.dylib 2>/dev/null || true

    # Last, and not optional on Apple silicon: editing a Mach-O invalidates its
    # signature, and an arm64 binary with a broken signature is killed on
    # launch rather than run. `install_name_tool` and `strip` both edit, so
    # everything touched above is signed again here — ad-hoc, which is what an
    # unsigned local build carries anyway.
    for f in "${stage}"/bin/* "${stage}"/lib/*.dylib; do
        codesign --force --sign - "${f}" >/dev/null 2>&1 || true
    done

    for app in "${apps[@]}"; do
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

# ------------------------------------------------------------------ Verify
#
# The point of the bundle is that it runs somewhere other than here, and every
# way of getting that wrong looks fine on the machine that built it — the
# libraries are installed here, so anything missed resolves anyway. So the
# check deliberately does *not* let the build machine answer: `LD_LIBRARY_PATH`
# is the bundle and nothing else.
#
# This is not hypothetical. The first bundle this produced was missing every
# OpenCV library, passed CI, and failed on the first plain Ubuntu it met with
# `libopencv_videoio.so.411: cannot open shared object file`.
case "$(uname -s)" in
Linux)
    # Read the `NEEDED` entries rather than asking the loader. `ldd` answers
    # from whatever is installed here — on a machine with OpenCV in
    # `/usr/lib`, a bundle missing every OpenCV library resolves perfectly and
    # the check passes. This asks a different question: is each name either in
    # the bundle, or on the short list the host is expected to provide? The
    # answer does not depend on the machine, which is the whole point.
    missing=0
    while IFS= read -r -d '' f; do
        while read -r soname; do
            if is_host_library "${soname}"; then
                continue
            fi
            if [ -e "${stage}/lib/${soname}" ]; then
                continue
            fi
            echo "missing from the bundle: ${soname} (needed by $(basename "${f}"))" >&2
            missing=1
        done < <(readelf -d "${f}" 2>/dev/null \
                    | awk -F'[][]' '/NEEDED/{print $2}')
    done < <(find "${stage}/bin" "${stage}/lib" -type f -print0)
    if [ "${missing}" -ne 0 ]; then
        echo "the bundle does not carry what it needs; it would fail to start elsewhere" >&2
        exit 1
    fi
    ;;
Darwin)
    # Nothing outside the bundle, the system, or `@rpath` — an absolute path
    # into Homebrew or the build tree is a library that will not be there.
    missing=0
    for f in "${stage}"/bin/* "${stage}"/lib/*.dylib; do
        while read -r dep; do
            case "${dep}" in
                @*|/usr/lib/*|/System/*) continue;;
            esac
            echo "points outside the bundle: $(basename "${f}") -> ${dep}" >&2
            missing=1
        done < <(otool -L "${f}" | tail -n +2 | awk '{print $1}')
    done
    if [ "${missing}" -ne 0 ]; then
        echo "the bundle references libraries it does not carry" >&2
        exit 1
    fi
    ;;
esac

echo "bundled into ${stage}:"
ls -l "${stage}" "${stage}/bin"
echo "libraries: $(find "${stage}/lib" -type f | wc -l)"
echo "verified: every library it needs is either carried or expected from the host"
