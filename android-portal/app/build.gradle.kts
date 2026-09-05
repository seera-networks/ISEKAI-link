plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
}

// ── The Rust core, and the bindings onto it ──────────────────────────────────
// Mirrors android/app/build.gradle.kts's two-task pattern exactly, pointed at
// the new portal-client-ffi crate instead of isekai-client-ffi. Neither the
// bindings nor the .so are committed, same reasoning as the camera app.

val uniffiOutputDir = layout.buildDirectory.dir("generated/uniffi")

/** The workspace root, two directories up from `android-portal/app`. */
val rustDir = rootProject.file("../rust")

val generateUniFfiBindings by tasks.registering(Exec::class) {
    group = "build"
    description = "Generate the Kotlin bindings from portal-client-ffi"
    workingDir = rustDir
    outputs.dir(uniffiOutputDir)
    inputs.files(fileTree("$rustDir/portal-client-ffi/src"))
    commandLine(
        "sh", "-c",
        listOf(
            "set -eu",
            "cd portal-client-ffi",
            "cargo build",
            "LIB=${'$'}(ls target/debug/libportal_client_ffi.so 2>/dev/null " +
                "|| ls target/debug/libportal_client_ffi.dylib)",
            "./target/debug/uniffi-bindgen generate --library \"${'$'}LIB\" " +
                "--language kotlin --out-dir \"${uniffiOutputDir.get().asFile}\"",
        ).joinToString("\n"),
    )
}

val generateJniLibs by tasks.registering(Exec::class) {
    group = "build"
    description = "Cross-compile portal-client-ffi into app/src/main/jniLibs"
    workingDir = file("$rustDir/portal-client-ffi")
    commandLine(
        "cargo", "ndk",
        "-t", "arm64-v8a",
        // Same floor as the camera app, same reason: seera-msquic's
        // selfsign_openssl.c needs glob()/globfree(), bionic only declares
        // those from API 28, and the whole native cross-compile targets 29
        // for consistency with quictls's own hardcoded sub-build API level.
        "--platform", "29",
        "-o", file("src/main/jniLibs").absolutePath,
        "build",
    )
    doLast {
        // cargo-ndk only copies portal-client-ffi's own cdylib. As of the
        // upstream portal-core migration, seera-msquic's build.rs produces
        // msquic as a *separate* shared object beside it rather than linking
        // it statically, and libportal_client_ffi.so dlopens that at
        // runtime -- confirmed the hard way by a `library "libmsquic.so" not
        // found` UnsatisfiedLinkError on every native call (silently
        // swallowed at startup by endpointIdOf's runCatching, so the app
        // looked fine until Pair/Connect crashed the process outright). Copy
        // it in by hand alongside the crate's own .so.
        val libmsquic = fileTree("$rustDir/portal-client-ffi/target/aarch64-linux-android/debug/build") {
            include("**/out/lib/libmsquic.so")
        }.files.maxByOrNull { it.lastModified() }
            ?: throw GradleException(
                "libmsquic.so not found under portal-client-ffi's aarch64-linux-android build output"
            )
        copy {
            from(libmsquic)
            into(file("src/main/jniLibs/arm64-v8a"))
        }
    }
}

android {
    namespace = "tools.isekai.portalclient"
    compileSdk = 34
    // Without this AGP has no NDK to find `llvm-strip` in and packages
    // libportal_client_ffi.so exactly as cargo-ndk wrote it -- a debug build
    // statically linking OpenSSL/quictls, ~200MB unstripped. That size is
    // what made a routine wireless `adb install` stall for minutes.
    ndkVersion = "29.0.14206865"

    defaultConfig {
        applicationId = "tools.isekai.portalclient"
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
        kotlinCompilerExtensionVersion = "1.5.14"
    }
}

tasks.withType<org.jetbrains.kotlin.gradle.tasks.KotlinCompile>().configureEach {
    dependsOn(generateUniFfiBindings)
}

dependencies {
    implementation("net.java.dev.jna:jna:5.14.0@aar")

    val composeBom = platform("androidx.compose:compose-bom:2024.06.00")
    implementation(composeBom)
    implementation("androidx.compose.ui:ui")
    implementation("androidx.compose.material3:material3")
    implementation("androidx.compose.ui:ui-tooling-preview")
    implementation("androidx.activity:activity-compose:1.9.0")
    implementation("androidx.lifecycle:lifecycle-viewmodel-compose:2.8.2")
    implementation("androidx.lifecycle:lifecycle-runtime-compose:2.8.2")
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-android:1.8.1")
    // Real Auth0 sign-in (Authorization Code + PKCE via a Custom Tab, plus
    // encrypted storage for the resulting session) -- same versions as the
    // camera app's own build.gradle.kts.
    implementation("androidx.browser:browser:1.8.0")
    implementation("androidx.security:security-crypto:1.1.0-alpha06")
    debugImplementation("androidx.compose.ui:ui-tooling")
}
