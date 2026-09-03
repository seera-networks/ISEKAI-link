package tools.isekai.cameraclient

import android.content.Context
import android.content.SharedPreferences

/**
 * Everything the connect screen collects apart from the secrets, which live
 * in [SecureStore]. Persisted so a dev round-trip does not mean retyping
 * fields; the defaults match the desktop `camera-client` and the iOS app's
 * own `ViewerSettings`.
 */
data class ViewerSettings(
    var identityUrl: String = "https://identity.isekai.tools:9443",
    var proxyUrl: String = "https://link.isekai.tools:6443",
    var protocolName: String = "isekai-validator-v1",
    var capability: String = "",
    var listenerId: String = "",
    // Which Endpoint `listenerId` is expected to be, from the camera it was
    // picked from -- kept so connecting can hold the proxy's answer against
    // it (`camera_core::paired`). Empty for a hand-typed listener, which
    // brings no pairing to check against. Mirrors the iOS app's own
    // `expectedEndpoint`.
    var expectedEndpoint: String = "",
    var register: Boolean = true,
    // Dev only. Accepts self-signed proxy/Identity certificates. Defaults to
    // false now that IsekaiApplication installs a real CA bundle
    // (SSL_CERT_FILE) -- see ~/isekai-link-android-camera-client-setup.md,
    // task 7, for the bug this used to work around.
    var insecureSkipVerify: Boolean = false,
    var enableMigration: Boolean = true,
    var logFilter: String = "",
) {
    companion object {
        private const val PREFS_NAME = "viewer_settings"

        fun load(context: Context): ViewerSettings {
            val prefs = prefs(context)
            val defaults = ViewerSettings()
            return ViewerSettings(
                identityUrl = prefs.getString("identityUrl", defaults.identityUrl)!!,
                proxyUrl = prefs.getString("proxyUrl", defaults.proxyUrl)!!,
                protocolName = prefs.getString("protocolName", defaults.protocolName)!!,
                capability = prefs.getString("capability", defaults.capability)!!,
                listenerId = prefs.getString("listenerId", defaults.listenerId)!!,
                expectedEndpoint =
                    prefs.getString("expectedEndpoint", defaults.expectedEndpoint)!!,
                register = prefs.getBoolean("register", defaults.register),
                insecureSkipVerify =
                    prefs.getBoolean("insecureSkipVerify", defaults.insecureSkipVerify),
                enableMigration = prefs.getBoolean("enableMigration", defaults.enableMigration),
                logFilter = prefs.getString("logFilter", defaults.logFilter)!!,
            )
        }

        private fun prefs(context: Context): SharedPreferences =
            context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
    }

    fun save(context: Context) {
        prefs(context).edit()
            .putString("identityUrl", identityUrl)
            .putString("proxyUrl", proxyUrl)
            .putString("protocolName", protocolName)
            .putString("capability", capability)
            .putString("listenerId", listenerId)
            .putString("expectedEndpoint", expectedEndpoint)
            .putBoolean("register", register)
            .putBoolean("insecureSkipVerify", insecureSkipVerify)
            .putBoolean("enableMigration", enableMigration)
            .putString("logFilter", logFilter)
            .apply()
    }
}
