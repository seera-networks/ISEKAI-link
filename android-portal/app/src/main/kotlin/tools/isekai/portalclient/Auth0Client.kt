package tools.isekai.portalclient

import android.content.Context
import android.net.Uri
import android.util.Base64
import androidx.browser.customtabs.CustomTabsIntent
import java.net.HttpURLConnection
import java.net.URL
import java.net.URLEncoder
import java.security.MessageDigest
import java.security.SecureRandom
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import org.json.JSONObject

/** The tokens a login (or a refresh) produced. */
data class Auth0Tokens(
    val accessToken: String,
    val refreshToken: String?,
    /** Epoch milliseconds. */
    val expiresAt: Long,
) {
    /**
     * Treats a token about to expire as expired: the Identity API checks
     * `exp` when the request lands, not when it was sent.
     */
    fun isExpired(
        now: Long = System.currentTimeMillis(),
        marginMs: Long = 60_000,
    ): Boolean = expiresAt - marginMs <= now

    fun toJson(): String =
        JSONObject()
            .put("accessToken", accessToken)
            .put("refreshToken", refreshToken)
            .put("expiresAt", expiresAt)
            .toString()

    companion object {
        fun fromJson(json: String): Auth0Tokens? =
            try {
                val obj = JSONObject(json)
                Auth0Tokens(
                    accessToken = obj.getString("accessToken"),
                    refreshToken = obj.optString("refreshToken").takeIf { it.isNotEmpty() && it != "null" },
                    expiresAt = obj.getLong("expiresAt"),
                )
            } catch (e: Exception) {
                null
            }
    }
}

/**
 * Bridges the Auth0 redirect (an Android Intent, delivered to whatever
 * Activity is on top when the Custom Tab closes) back to the suspended
 * coroutine that started the login. Mirrors `cameraclient.Auth0CallbackBroker`
 * exactly -- this is a separate object, not a shared one, since each app's
 * redirect lands in its own process.
 */
object Auth0CallbackBroker {
    private var pending: CompletableDeferred<Uri>? = null

    fun beginWaiting(): CompletableDeferred<Uri> {
        val deferred = CompletableDeferred<Uri>()
        pending = deferred
        return deferred
    }

    /** Called from MainActivity.onNewIntent. Returns whether it was expected. */
    fun handleRedirect(uri: Uri): Boolean {
        val current = pending ?: return false
        pending = null
        current.complete(uri)
        return true
    }

    fun cancelPending() {
        pending?.cancel()
        pending = null
    }
}

/**
 * Auth0 Authorization Code flow with PKCE, through a Custom Tab. Identical
 * logic to `cameraclient.Auth0Client` -- see that file's notes on why this is
 * hand-rolled rather than the Auth0 Android SDK, and why a Custom Tab rather
 * than a WebView.
 */
class Auth0Client(private val context: Context) {
    sealed class Failure(message: String) : Exception(message) {
        object NotConfigured : Failure("Auth0 is not configured")

        object Cancelled : Failure("Sign-in was cancelled")

        object CouldNotStart : Failure("Could not open the sign-in page")

        class BadCallback(detail: String) : Failure("Unexpected sign-in response: $detail")

        object StateMismatch : Failure("Sign-in response did not match the request")

        class Server(detail: String) : Failure(detail)
    }

    suspend fun logIn(): Auth0Tokens {
        val verifier = randomUrlSafeString()
        val state = randomUrlSafeString(16)
        val authorizeUri = authorizeUri(challengeFor(verifier), state)

        val deferred = Auth0CallbackBroker.beginWaiting()
        if (!launchCustomTab(authorizeUri)) {
            Auth0CallbackBroker.cancelPending()
            throw Failure.CouldNotStart
        }

        val callback =
            try {
                deferred.await()
            } catch (e: CancellationException) {
                throw Failure.Cancelled
            }

        callback.getQueryParameter("error")?.let { error ->
            throw Failure.Server(callback.getQueryParameter("error_description") ?: error)
        }
        if (callback.getQueryParameter("state") != state) throw Failure.StateMismatch
        val code = callback.getQueryParameter("code") ?: throw Failure.BadCallback("no authorization code")

        return requestTokens(
            mapOf(
                "grant_type" to "authorization_code",
                "client_id" to Auth0Config.CLIENT_ID,
                "code" to code,
                "code_verifier" to verifier,
                "redirect_uri" to Auth0Config.REDIRECT_URI,
            ),
        )
    }

    /**
     * Exchange a refresh token for a fresh access token. Auth0 may or may not
     * return a new refresh token depending on whether rotation is enabled, so
     * the caller keeps the old one when it does not.
     */
    suspend fun refresh(refreshToken: String): Auth0Tokens =
        requestTokens(
            mapOf(
                "grant_type" to "refresh_token",
                "client_id" to Auth0Config.CLIENT_ID,
                "refresh_token" to refreshToken,
            ),
        )

    private fun authorizeUri(
        challenge: String,
        state: String,
    ): Uri =
        Uri.parse("https://${Auth0Config.DOMAIN}/authorize").buildUpon()
            .appendQueryParameter("response_type", "code")
            .appendQueryParameter("client_id", Auth0Config.CLIENT_ID)
            .appendQueryParameter("redirect_uri", Auth0Config.REDIRECT_URI)
            .appendQueryParameter("scope", Auth0Config.SCOPE)
            .appendQueryParameter("audience", Auth0Config.AUDIENCE)
            .appendQueryParameter("state", state)
            .appendQueryParameter("code_challenge", challenge)
            .appendQueryParameter("code_challenge_method", "S256")
            .build()

    private fun launchCustomTab(uri: Uri): Boolean =
        try {
            val customTabsIntent = CustomTabsIntent.Builder().build()
            // AuthStore (and therefore this client) is constructed with the
            // ViewModel/Composable's Application context, not an Activity
            // one -- an Application context isn't itself part of a task back
            // stack, so Android requires this flag before it will let it
            // start an activity at all.
            customTabsIntent.intent.addFlags(android.content.Intent.FLAG_ACTIVITY_NEW_TASK)
            customTabsIntent.launchUrl(context, uri)
            true
        } catch (e: Exception) {
            android.util.Log.e("PortalFFI", "launchCustomTab failed", e)
            false
        }

    private suspend fun requestTokens(parameters: Map<String, String>): Auth0Tokens =
        withContext(Dispatchers.IO) {
            val connection = URL("https://${Auth0Config.DOMAIN}/oauth/token").openConnection() as HttpURLConnection
            try {
                connection.requestMethod = "POST"
                connection.doOutput = true
                connection.setRequestProperty("Content-Type", "application/x-www-form-urlencoded")
                connection.outputStream.use { it.write(formEncode(parameters).toByteArray()) }

                val status = connection.responseCode
                val body =
                    (if (status in 200..299) connection.inputStream else connection.errorStream)
                        .bufferedReader()
                        .use { it.readText() }

                if (status !in 200..299) {
                    val json = try { JSONObject(body) } catch (e: Exception) { null }
                    val detail =
                        json?.optString("error_description")?.takeIf { it.isNotEmpty() }
                            ?: json?.optString("error")?.takeIf { it.isNotEmpty() }
                            ?: "Auth0 returned HTTP $status"
                    throw Failure.Server(detail)
                }

                val json = JSONObject(body)
                Auth0Tokens(
                    accessToken = json.getString("access_token"),
                    refreshToken = json.optString("refresh_token").takeIf { it.isNotEmpty() },
                    expiresAt = System.currentTimeMillis() + json.getLong("expires_in") * 1000,
                )
            } finally {
                connection.disconnect()
            }
        }

    private fun formEncode(parameters: Map<String, String>): String =
        parameters.entries.joinToString("&") { (k, v) ->
            "${URLEncoder.encode(k, "UTF-8")}=${URLEncoder.encode(v, "UTF-8")}"
        }

    private fun randomUrlSafeString(byteCount: Int = 32): String {
        val bytes = ByteArray(byteCount)
        SecureRandom().nextBytes(bytes)
        return Base64.encodeToString(bytes, Base64.URL_SAFE or Base64.NO_PADDING or Base64.NO_WRAP)
    }

    private fun challengeFor(verifier: String): String {
        val digest = MessageDigest.getInstance("SHA-256").digest(verifier.toByteArray())
        return Base64.encodeToString(digest, Base64.URL_SAFE or Base64.NO_PADDING or Base64.NO_WRAP)
    }
}
