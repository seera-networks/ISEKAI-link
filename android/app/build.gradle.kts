plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
}

// ── The Rust core, and the bindings onto it ──────────────────────────────────
//
// Neither is committed. The bindings are generated from the Rust interface, so
// a copy in the tree is a copy that goes stale — the interface changes, the
// Kotlin does not, and nothing says so until an app that compiled fine fails at
// runtime. iOS generates its Swift bindings from the built library for exactly
// this reason (`.github/workflows/ios-ffi.yml`), and this is the same shape.

/// Where `uniffi-bindgen` writes, and where Kotlin compilation reads from.
val uniffiOutputDir = layout.buildDirectory.dir("generated/uniffi")

/// The workspace root, two directories up from `android/app`.
val rustDir = rootProject.file("../rust")

/// Build the FFI crate **for the host** and generate the Kotlin bindings from
/// the library it produces.
///
/// The host build is deliberate: `uniffi-bindgen` reads the interface out of
/// any build of the crate, and the interface does not vary by target. Making
/// this wait on the Android cross-compile would tie a Kotlin-only step to the
/// NDK.
val generateUniFfiBindings by tasks.registering(Exec::class) {
    group = "build"
    description = "Generate the Kotlin bindings from isekai-client-ffi"
    workingDir = rustDir
    outputs.dir(uniffiOutputDir)
    // Rebuild when the interface could have moved.
    inputs.files(fileTree("$rustDir/isekai-client-ffi/src"))
    commandLine(
        "sh", "-c",
        listOf(
            "set -eu",
            "cargo build -p isekai-client-ffi",
            "LIB=${'$'}(ls target/debug/libisekai_client_ffi.so 2>/dev/null " +
                "|| ls target/debug/libisekai_client_ffi.dylib)",
            "./target/debug/uniffi-bindgen generate --library \"${'$'}LIB\" " +
                "--language kotlin --out-dir \"${uniffiOutputDir.get().asFile}\"",
        ).joinToString("\n"),
    )
}

/// Cross-compile the FFI crate for the ABIs the app ships, into `jniLibs`.
///
/// Separate from the bindings on purpose: this one needs the NDK and
/// `cargo-ndk`, and a developer who only wants the app to compile does not.
val generateJniLibs by tasks.registering(Exec::class) {
    group = "build"
    description = "Cross-compile isekai-client-ffi into app/src/main/jniLibs"
    workingDir = rustDir
    commandLine(
        "cargo", "ndk",
        "-t", "arm64-v8a",
        // The same API level as `minSdk` above, and as the `ANDROID_PLATFORM`
        // seera-msquic's build script passes to CMake. cargo-ndk defaults to
        // 21, which puts `--target=aarch64-linux-android21` in the CFLAGS
        // CMake inherits — and msquic's selfsign_openssl.c calls `glob()`,
        // which bionic only declares from 28. The two halves of the same
        // native build have to agree on this number.
        "-p", "29",
        "-o", file("src/main/jniLibs").absolutePath,
        "build", "-p", "isekai-client-ffi",
    )
}

android {
    namespace = "tools.isekai.cameraclient"
    compileSdk = 34

    defaultConfig {
        applicationId = "tools.isekai.cameraclient"
        // Matches the Rust core's own floor: seera-msquic's selfsign_openssl.c
        // calls glob()/globfree(), which bionic only declares starting at
        // API 28; the whole cross-compile targets 29 for consistency with
        // quictls's own hardcoded sub-build API level. See
        // ~/isekai-link-android-camera-client-setup.md on this machine for
        // the full story.
        minSdk = 29
        targetSdk = 34
        versionCode = 1
        versionName = "0.1"
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    kotlinOptions {
        jvmTarget = "17"
    }

    buildFeatures {
        compose = true
    }

    sourceSets {
        getByName("main") {
            kotlin.srcDir(uniffiOutputDir)
        }
    }

    composeOptions {
        // Paired with Kotlin 1.9.24 per the Compose-compiler/Kotlin
        // compatibility map.
        kotlinCompilerExtensionVersion = "1.5.14"
    }
}

// Kotlin cannot compile without the bindings, so generating them is not an
// optional extra step somebody has to remember.
tasks.withType<org.jetbrains.kotlin.gradle.tasks.KotlinCompile>().configureEach {
    dependsOn(generateUniFfiBindings)
}

dependencies {
    // UniFFI's generated Kotlin bindings load the native library via JNA.
    implementation("net.java.dev.jna:jna:5.14.0@aar")

    val composeBom = platform("androidx.compose:compose-bom:2024.06.00")
    implementation(composeBom)
    implementation("androidx.compose.ui:ui")
    implementation("androidx.compose.material3:material3")
    implementation("androidx.compose.ui:ui-tooling-preview")
    implementation("androidx.activity:activity-compose:1.9.0")
    implementation("androidx.lifecycle:lifecycle-viewmodel-compose:2.8.2")
    implementation("androidx.lifecycle:lifecycle-runtime-compose:2.8.2")
    // ProcessLifecycleOwner: whole-app foreground/background transitions, for
    // the suspend/resume-on-background policy (task 7) -- Android's
    // equivalent of iOS's scenePhase-driven connection suspend/resume
    // (docs/ios_camera_client_plan.md risk R3).
    implementation("androidx.lifecycle:lifecycle-process:2.8.2")
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-android:1.8.1")
    debugImplementation("androidx.compose.ui:ui-tooling")

    // Auth0 login: hand-rolled Authorization Code + PKCE through a Custom Tab,
    // same choice iOS made (ASWebAuthenticationSession) over pulling in the
    // full Auth0 SDK -- three requests and a hash doesn't need a dependency.
    implementation("androidx.browser:browser:1.8.0")

    // Encrypted storage for the endpoint key PEM and the Auth0 session --
    // Android's equivalent of iOS's Keychain.
    implementation("androidx.security:security-crypto:1.1.0-alpha06")

    // QR pairing: CameraX for the preview/analysis pipeline, ML Kit for the
    // actual barcode decode.
    val cameraxVersion = "1.3.4"
    implementation("androidx.camera:camera-core:$cameraxVersion")
    implementation("androidx.camera:camera-camera2:$cameraxVersion")
    implementation("androidx.camera:camera-lifecycle:$cameraxVersion")
    implementation("androidx.camera:camera-view:$cameraxVersion")
    implementation("com.google.mlkit:barcode-scanning:17.3.0")
}
