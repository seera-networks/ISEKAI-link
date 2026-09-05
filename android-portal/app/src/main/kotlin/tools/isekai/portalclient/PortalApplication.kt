package tools.isekai.portalclient

import android.app.Application
import android.system.Os
import android.util.Log
import java.io.File

private const val TAG = "PortalFFI"

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
