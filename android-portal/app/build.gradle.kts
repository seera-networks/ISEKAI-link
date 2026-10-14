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

/** cargo's target triple for each Android ABI name. */
val rustTargetOf = mapOf(
    "arm64-v8a" to "aarch64-linux-android",
    "x86_64" to "x86_64-linux-android",
    "armeabi-v7a" to "armv7-linux-androideabi",
    "x86" to "i686-linux-android",
)

/**
 * Which ABIs to cross-compile for.
 *
 * **`arm64-v8a` alone is what a phone needs, and what every release should
 * carry.** An emulator on an x86_64 host needs `x86_64` as well, and an arm64
 * system image is not an answer there: there is no hardware acceleration for
 * it, so the image falls back to full instruction emulation. Running this app
 * against an emulator -- which is the only way to exercise it without a phone
 * in hand, and the only way to drive a network change on demand -- therefore
 * means building a second ABI:
 *
 *     ./gradlew -PportalAbis=arm64-v8a,x86_64 assembleDebug
 *
 * A property rather than a second hardcoded entry, because each ABI is a full
 * native build of msquic and quictls: paying for both on every phone build
 * would be minutes for nothing.
 */
val portalAbis: List<String> = run {
    // `-PportalAbis=` and a trailing comma both yield an empty element, which
    // would reach `cargo ndk -t "" build`. A bare `-PportalAbis=` is a
    // non-null empty string, so a `?:` on the property alone does not catch
    // it; the default has to be applied after the blanks are gone.
    val asked = (findProperty("portalAbis") as String? ?: "")
        .split(",").map { it.trim() }.filter { it.isNotEmpty() }
    val abis = asked.ifEmpty { listOf("arm64-v8a") }
    // **Checked here, not in `doLast`.** cargo-ndk's `-t` takes an ABI name or
    // a target triple, so `-PportalAbis=aarch64-linux-android` builds happily
    // for minutes before the triple lookup below fails. Configuration time
    // costs a second.
    val unknown = abis.filter { it !in rustTargetOf }
    if (unknown.isNotEmpty()) {
        throw GradleException(
            "unknown ABI(s) ${unknown.joinToString(", ")} in -PportalAbis. " +
                "Known: ${rustTargetOf.keys.joinToString(", ")}"
        )
    }
    abis
}

val generateJniLibs by tasks.registering(Exec::class) {
    group = "build"
    description = "Cross-compile portal-client-ffi into app/src/main/jniLibs"
    workingDir = file("$rustDir/portal-client-ffi")
    doFirst {
        // **Sweep the ABIs we are not building.** `src/main/jniLibs` is a
        // source directory: cargo-ndk and the copy below only ever write into
        // it, and nothing cleans it, so a `.so` from an earlier build with a
        // different `-PportalAbis` simply stays and gets packaged.
        //
        // That is not cosmetic. Build both ABIs for an emulator, change the
        // Rust, then run a plain `./gradlew installDebug` (default
        // `arm64-v8a`): the x86_64 pair is left untouched, AGP packages it,
        // and on an x86_64 emulator the loader prefers it -- so the emulator
        // runs the **previous** native build while reporting success. A
        // wrong-architecture `.so` fails loudly at install; a stale
        // right-architecture one is the quiet kind of wrong this file's other
        // comments are all about.
        file("src/main/jniLibs").listFiles()
            ?.filter { it.isDirectory && it.name !in portalAbis }
            ?.forEach {
                logger.lifecycle("generateJniLibs: removing stale ${it.name} libraries")
                it.deleteRecursively()
            }
    }
    commandLine(
        listOf("cargo", "ndk") +
            portalAbis.flatMap { listOf("-t", it) } +
            listOf(
                // Same floor as the camera app, same reason: seera-msquic's
                // selfsign_openssl.c needs glob()/globfree(), bionic only
                // declares those from API 28, and the whole native
                // cross-compile targets 29 for consistency with quictls's own
                // hardcoded sub-build API level.
                "--platform", "29",
                "-o", file("src/main/jniLibs").absolutePath,
                "build",
            ),
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
        //
        // **Per ABI.** Each one builds its own msquic, and a .so from the
        // wrong architecture in a jniLibs directory is an install-time
        // failure rather than a build one.
        for (abi in portalAbis) {
            // Non-null: `portalAbis` is validated against this map above.
            val triple = rustTargetOf.getValue(abi)
            val libmsquic = fileTree("$rustDir/portal-client-ffi/target/$triple/debug/build") {
                include("**/out/lib/libmsquic.so")
            }.files.maxByOrNull { it.lastModified() }
                ?: throw GradleException(
                    "libmsquic.so not found under portal-client-ffi's $triple build output"
                )
            copy {
                from(libmsquic)
                into(file("src/main/jniLibs/$abi"))
            }
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

// `generateJniLibs` was registered but nothing ever depended on it, so
// `assembleDebug`/`installDebug` packaged whatever happened to already be
// sitting in `src/main/jniLibs` -- nothing, on a fresh checkout -- and
// produced an APK that launches fine (native calls are lazy) and then hits
// `UnsatisfiedLinkError: library "libportal_client_ffi.so" not found` the
// first time one actually runs (confirmed live: Pair crashed the process
// outright). Every AGP variant has its own `merge<Variant>JniLibFolders` task
// that gathers `src/main/jniLibs` right before packaging; hooking there
// (rather than `KotlinCompile`, like the bindings above) keeps a Kotlin-only
// compile from requiring the NDK, per `generateJniLibs`'s own doc comment,
// while still guaranteeing every real build actually has the library it
// needs to run.
tasks.matching { it.name.startsWith("merge") && it.name.endsWith("JniLibFolders") }
    .configureEach { dependsOn(generateJniLibs) }

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
