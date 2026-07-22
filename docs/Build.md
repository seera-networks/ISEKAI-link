# ISEKAI Link Build Guide

This document describes how to build ISEKAI Link from source.

## Table of Contents

- [Overview](#overview)
- [Prerequisites](#prerequisites)
- [1. Clone the repository](#1-clone-the-repository)
- [2. Prepare the submodules](#2-prepare-the-submodules)
- [3. Install OpenCV / libclang (for camera-server & camera-client)](#3-install-opencv--libclang-for-camera-server--camera-client)
- [4. Build](#4-build)
- [5. Run](#5-run)
- [Troubleshooting](#troubleshooting)

---

## Overview

ISEKAI Link is a Rust workspace. The sources live under the `rust/` directory and consist of the following crates:

| Crate | Kind | Extra external dependencies |
| --- | --- | --- |
| `agent` | binary | — |
| `camera-server` | binary | **OpenCV 4.11+ / libclang** |
| `camera-client` | binary | **OpenCV 4.11+ / libclang** |
| `camera-core` | library | — |
| `channel-masque` | library | — |
| `isekai-p2p` | library | — |
| `isekai-p2p-core` | library | — |
| `utils` | library | — |
| `webrtc-app` | binary | — |

The QUIC transport uses [`msquic-async-rs`](https://github.com/masa-koz/msquic-async-rs) (which builds MsQuic natively) and [`tonic-h3`](https://github.com/masa-koz/tonic-h3) under `submodules/`. These are pulled in as submodules, so you must initialize and prepare them using the steps below.

---

## Prerequisites

Install the following before building:

- **Git**
- **Rust toolchain** (installing via `rustup` is recommended; **rustc 1.88.0 or later is required** — a transitive dependency, `time-macros`, does not build on older compilers. Verified with 1.96.0)
  - <https://rustup.rs/>
  - If your default `stable` is older than 1.88, update it with `rustup update stable`, or build with a newer installed toolchain, e.g. `cargo +1.96.0 build`.
- **C/C++ build tools** (required to build MsQuic natively)
  - Windows: the "Desktop development with C++" workload from Visual Studio 2022, or the Build Tools for Visual Studio
  - Linux: `build-essential`, `cmake`, `perl`, etc. (`prepare-machine.ps1` installs the required packages)
- **PowerShell 7 (`pwsh`)** — used to run the submodule build-preparation script
  - Required on Linux/macOS too: <https://learn.microsoft.com/powershell/scripting/install/installing-powershell>

To build `camera-server` / `camera-client`, you additionally need **OpenCV 4.11 or later** and **libclang** (see [step 3](#3-install-opencv--libclang-for-camera-server--camera-client)).

---

## 1. Clone the repository

```sh
git clone https://github.com/masa-koz/ISEKAI-link.git
cd ISEKAI-link
```

---

## 2. Prepare the submodules

Set up the sources and native libraries for the QUIC/HTTP3 transport. The commands below start from the repository root.

### 2-1. Initialize the top-level submodules

```sh
cd submodules
git submodule update --init msquic-async-rs tonic-h3
```

### 2-2. Initialize the nested submodules of `msquic-async-rs`

```sh
cd msquic-async-rs
git submodule update --init msquic seera-msquic
```

### 2-3. Prepare the MsQuic build (`seera-msquic`)

Run `prepare-machine.ps1` from `seera-msquic` to set up the dependencies needed to build MsQuic. **Run it with PowerShell 7 (`pwsh`).**

> [!IMPORTANT]
> This script takes a different TLS provider depending on the OS.

#### On Windows

Run it in an **elevated (Administrator) `pwsh`** (uses schannel):

```powershell
cd seera-msquic
scripts/prepare-machine.ps1 -Tls schannel -ForBuild
```

#### On Linux

Run it with `pwsh` (uses quictls):

```sh
cd seera-msquic
pwsh scripts/prepare-machine.ps1 -Tls quictls -ForBuild
```

> [!NOTE]
> On Linux the script may prompt for a `sudo` password. You can press **`Ctrl+C`** to skip it; the subsequent build will still work.

Once preparation is complete, return to the repository root:

```sh
cd ../../..
```

---

## 3. Install OpenCV / libclang (for camera-server & camera-client)

`camera-server` and `camera-client` use the [`opencv`](https://crates.io/crates/opencv) crate. Building them requires **OpenCV 4.11 or later** and **libclang** (used to generate the bindings) installed locally.

> [!NOTE]
> If you only build crates other than `camera-*` (i.e. `agent`, `webrtc-app`, and the libraries), this step is not required. In that case, target specific crates in [step 4](#4-build).

### Windows

Using [vcpkg](https://github.com/microsoft/vcpkg) is the easiest approach. The steps below are verified to produce a successful build.

#### a. Install libclang (LLVM)

**libclang must be new enough for your MSVC toolchain's standard library.** With current Visual Studio 2022 (MSVC 14.4x), the OpenCV binding generator fails on older libclang with:

```
yvals_core.h: error STL1000: Unexpected compiler version, expected Clang 19.0.0 or newer.
```

Install the latest LLVM (22.x at time of writing satisfies this):

```powershell
winget install --id LLVM.LLVM -e
# If an older LLVM is already installed, force the upgrade:
winget install --id LLVM.LLVM -e --force
```

Then point `LIBCLANG_PATH` at it (and confirm the version is >= 19):

```powershell
$env:LIBCLANG_PATH = "C:\Program Files\LLVM\bin"
& "$env:LIBCLANG_PATH\clang.exe" --version   # must report 19.0.0 or newer
```

#### b. Install OpenCV via vcpkg

```powershell
# Get and bootstrap vcpkg (if not already installed)
git clone https://github.com/microsoft/vcpkg.git C:\vcpkg
C:\vcpkg\bootstrap-vcpkg.bat

# Install OpenCV (default features install 4.12.x; includes the Windows msmf/dshow
# videoio backends). The camera crates only need core/imgproc/imgcodecs/videoio,
# so contrib/nonfree are NOT required — plain opencv4 keeps the build far shorter.
C:\vcpkg\vcpkg.exe install opencv4:x64-windows
```

> [!NOTE]
> This is a from-source build and takes a while (roughly ~1 hour on a typical machine, mostly OpenCV + protobuf).

#### c. Point the `opencv` crate at the vcpkg install

The `opencv` crate's automatic vcpkg probe did **not** reliably emit the link flags in testing (it also picked the debug import libs, whose CRT mismatches Rust's release CRT and causes `LNK2019` unresolved-symbol errors). Setting the `OPENCV_*` variables explicitly — pointing at the **release** libs — is the reliable path. Set these before building the camera crates:

```powershell
$env:OPENCV_INCLUDE_PATHS = "C:\vcpkg\installed\x64-windows\include\opencv4"
$env:OPENCV_LINK_PATHS    = "C:\vcpkg\installed\x64-windows\lib"
$env:OPENCV_LINK_LIBS     = "opencv_core4,opencv_imgproc4,opencv_imgcodecs4,opencv_videoio4"
$env:OPENCV_MSVC_CRT      = "dynamic"   # must be "dynamic" or "static" (x64-windows is dynamic)
# Needed at runtime so the OpenCV DLLs are found:
$env:PATH = "C:\vcpkg\installed\x64-windows\bin;$env:LIBCLANG_PATH;$env:PATH"
```

> [!TIP]
> To make these persistent across shells, set them as user/system environment variables (e.g. via `setx` or *System Properties → Environment Variables*) instead of per-session `$env:` assignments.

### Linux (Debian / Ubuntu)

```sh
sudo apt-get update
sudo apt-get install -y libopencv-dev clang libclang-dev
```

> [!NOTE]
> If your distribution's OpenCV package is older than 4.11, install a newer build following the [official OpenCV build instructions](https://docs.opencv.org/4.x/d7/d9f/tutorial_linux_install.html) or use a repository that provides a newer package.

You can verify the installation with:

```sh
pkg-config --modversion opencv4   # must be 4.11 or later
clang --version
```

### Reference

For OpenCV crate build settings (`OPENCV_LINK_LIBS`, `OPENCV_INCLUDE_PATHS`, `OPENCV_LINK_PATHS`, etc.) and environment-specific details, see the upstream documentation:

- <https://github.com/twistedfall/opencv-rust/blob/master/INSTALL.md>

---

## 4. Build

The workspace is located in the `rust/` directory.

```sh
cd rust
```

### Build the entire workspace

(when OpenCV / libclang are installed, and — on Windows — the `OPENCV_*` variables from
[step 3c](#3-install-opencv--libclang-for-camera-server--camera-client) are set)

```sh
cargo build
# Release build:
cargo build --release
```

> [!NOTE]
> Remember rustc must be >= 1.88 (see [Prerequisites](#prerequisites)). If your default
> `stable` is older, either `rustup update stable` or select a newer toolchain per invocation,
> e.g. `cargo +1.96.0 build`.

### Build a specific crate only

To build the non-camera crates without installing OpenCV, target them with `-p`:

```sh
cargo build -p agent
cargo build -p webrtc-app
```

To build the camera apps:

```sh
cargo build -p camera-server
cargo build -p camera-client
```

---

## 5. Run

Binary crates can be run with `cargo run` (from within the `rust/` directory):

```sh
cargo run -p camera-server
cargo run -p camera-client
cargo run -p agent
cargo run -p webrtc-app
```

Check the command-line arguments of each binary with `-- --help`:

```sh
cargo run -p camera-server -- --help
```

---

## Troubleshooting

- **`msquic`-related link/build errors**
  Make sure the submodules are initialized (steps 2-1 and 2-2) and that `prepare-machine.ps1` has been run for your OS (step 2-3). Also confirm the TLS provider is correct (Windows: `schannel` / Linux: `quictls`).

- **`prepare-machine.ps1` is not found / cannot run**
  Make sure you are running it with `pwsh` (PowerShell 7). On Windows, an elevated (Administrator) `pwsh` is required.

- **OpenCV not found (`camera-*` build failure)**
  Confirm OpenCV 4.11 or later is installed and that `pkg-config --modversion opencv4` (Linux) or the vcpkg environment variables (Windows) are set correctly.

- **libclang not found**
  Install LLVM/Clang and make sure the `libclang` path is included in `LIBCLANG_PATH` (or `PATH`).

- **`error STL1000: Unexpected compiler version, expected Clang 19.0.0 or newer` (Windows)**
  Your libclang is too old for the installed MSVC standard library. Upgrade LLVM to 19+ (see [step 3a](#3-install-opencv--libclang-for-camera-server--camera-client)) and re-point `LIBCLANG_PATH`.

- **`LNK2019: unresolved external symbol "public: ... cv::..."` (Windows)**
  The OpenCV import libraries were not linked. Set `OPENCV_INCLUDE_PATHS` / `OPENCV_LINK_PATHS` / `OPENCV_LINK_LIBS` / `OPENCV_MSVC_CRT=dynamic` explicitly, pointing at the **release** libs under `installed\x64-windows\lib` (see [step 3c](#3-install-opencv--libclang-for-camera-server--camera-client)), then rebuild.

- **`Invalid value of OPENCV_MSVC_CRT var, expected "static" or "dynamic"`**
  `OPENCV_MSVC_CRT` only accepts `dynamic` or `static`. For a vcpkg `x64-windows` install, use `dynamic`.

- **`camera-*.exe` fails to start with a missing `opencv_*.dll` error**
  The OpenCV DLLs must be on `PATH` at runtime. Add `C:\vcpkg\installed\x64-windows\bin` to `PATH` (or copy the DLLs next to the executable).

- **When you only need the non-camera apps**
  Skip installing OpenCV / libclang and build only the target crate with `cargo build -p <crate>`.
