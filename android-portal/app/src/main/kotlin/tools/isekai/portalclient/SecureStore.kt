package tools.isekai.portalclient

import android.content.Context
import android.content.SharedPreferences
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKey

/**
 * Encrypted storage for the Auth0 session, mirroring `cameraclient.SecureStore`.
 * The endpoint key stays on plain internal storage (`endpoint_key.pem`, per
 * `MainActivity`'s existing comment on that) -- only the Auth0 tokens move to
 * encrypted storage here, since those are the credential that grants access
 * to the account, not just this one device's identity.
 */
object SecureStore {
    private const val FILE_NAME = "secure_store"

    /** The whole [Auth0Tokens] blob from a login, as JSON. */
    const val AUTH0_SESSION = "auth0-session"

    @Volatile
    private var prefsInstance: SharedPreferences? = null

    private fun prefs(context: Context): SharedPreferences {
        prefsInstance?.let { return it }
        synchronized(this) {
            prefsInstance?.let { return it }
            val masterKey =
                MasterKey.Builder(context.applicationContext)
                    .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
                    .build()
            val created =
                EncryptedSharedPreferences.create(
                    context.applicationContext,
                    FILE_NAME,
                    masterKey,
                    EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
                    EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM,
                )
            prefsInstance = created
            return created
        }
    }

    fun get(
        context: Context,
        key: String,
    ): String? = prefs(context).getString(key, null)

    fun set(
        context: Context,
        key: String,
        value: String,
    ) {
        prefs(context).edit().putString(key, value).apply()
    }

    fun delete(
        context: Context,
        key: String,
    ) {
        prefs(context).edit().remove(key).apply()
    }
}
