package tools.isekai.portalclient

import android.app.Application
import android.content.pm.ApplicationInfo
import android.system.Os
import android.util.Log
import uniffi.portal_client_ffi.initLogging
import java.io.File

private const val TAG = "PortalFFI"

/**
 * Rust log filters (`EnvFilter` syntax, e.g. "info,isekai_p2p=debug" to see
 * more of one crate), fixed when the app starts.
 *
 * Debug builds log at `info`: pairing, connect, relay and path switches, which
 * includes Endpoint ids and the address the device is seen from. Release builds
 * log only warnings and errors: the privacy policy (§3.5) describes diagnostic
 * logging as something the user switches on, so a release build must not
 * write session detail to the device log by default. A user-facing switch for
 * it would follow the camera app's "Log filter" setting.
 */
private const val RUST_LOG_FILTER_DEBUG = "info"
private const val RUST_LOG_FILTER_RELEASE = "warn"

/**
 * Sets up `SSL_CERT_FILE` and `XDG_CONFIG_HOME` before anything else in the
 * process runs — identical in effect to the camera app's own
 * `IsekaiApplication`. Both are core-runtime requirements of the shared Rust
 * P2P stack on Android, not camera-specific: without `SSL_CERT_FILE`, quictls
 * has no root CAs to validate a server's certificate chain against and every
 * real (non-insecure) TLS handshake fails; without `XDG_CONFIG_HOME`, the
 * shared `config_dir()` helper (used by the paired-Endpoint bookkeeping) falls
 * into a Linux/XDG branch that finds nowhere writable, since neither
 * `XDG_CONFIG_HOME` nor `HOME` is ever set in an Android app's process by
 * default. See the camera project's own troubleshooting history for how this
 * bit it for real the first time.
 */
class PortalApplication : Application() {
    override fun onCreate() {
        super.onCreate()
        try {
            Os.setenv("SSL_CERT_FILE", caBundleFile().absolutePath, true)
        } catch (e: Exception) {
            Log.e(TAG, "failed to install CA bundle", e)
        }
        try {
            Os.setenv("XDG_CONFIG_HOME", filesDir.absolutePath, true)
        } catch (e: Exception) {
            Log.e(TAG, "failed to set XDG_CONFIG_HOME", e)
        }
        // Before anything calls into Rust: without it, everything the Rust
        // side logs (pairing, connect, relay, path switches, its warnings) is
        // dropped. Read it with `adb logcat -s PortalFFI PortalRust`.
        val debuggable = (applicationInfo.flags and ApplicationInfo.FLAG_DEBUGGABLE) != 0
        try {
            initLogging(if (debuggable) RUST_LOG_FILTER_DEBUG else RUST_LOG_FILTER_RELEASE)
        } catch (e: Throwable) {
            Log.e(TAG, "failed to start Rust logging", e)
        }
    }

    private fun caBundleFile(): File {
        val out = File(filesDir, "cacert.pem")
        if (!out.exists() || out.length() == 0L) {
            assets.open("cacert.pem").use { input ->
                out.outputStream().use { output -> input.copyTo(output) }
            }
        }
        return out
    }
}
