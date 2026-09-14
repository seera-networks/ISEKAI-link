package tools.isekai.portalclient

import android.content.Context
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow

sealed class AuthError(message: String) : Exception(message) {
    object NotSignedIn : AuthError("Sign in to Auth0 first")

    object SessionExpired : AuthError("The session expired — sign in again")
}

/**
 * The signed-in session: tokens in encrypted storage, renewed when stale.
 * Mirrors `cameraclient.AuthStore` -- see that file for the reasoning behind
 * each piece; this is the same shape with `SecureStore.AUTH0_MANUAL_TOKEN`
 * dropped, since the manual-paste fallback field stays purely in Compose
 * state here rather than being persisted (it is meant as a one-off escape
 * hatch when Auth0 itself is unreachable, not a second credential to keep
 * around).
 */
class AuthStore(private val context: Context) {
    private val client = Auth0Client(context)

    private val _tokens = MutableStateFlow(loadFromStore())
    val tokens: StateFlow<Auth0Tokens?> = _tokens.asStateFlow()

    private val _isWorking = MutableStateFlow(false)
    val isWorking: StateFlow<Boolean> = _isWorking.asStateFlow()

    val isSignedIn: Boolean get() = _tokens.value != null

    suspend fun signIn() {
        _isWorking.value = true
        try {
            store(client.logIn())
        } finally {
            _isWorking.value = false
        }
    }

    fun signOut() {
        _tokens.value = null
        SecureStore.delete(context, SecureStore.AUTH0_SESSION)
    }

    /** An access token good for the request about to be made, renewed first if stale. */
    suspend fun accessToken(): String {
        val current = _tokens.value ?: throw AuthError.NotSignedIn
        if (!current.isExpired()) return current.accessToken

        val refreshToken =
            current.refreshToken ?: run {
                // No offline_access, so there is nothing to renew with.
                signOut()
                throw AuthError.SessionExpired
            }

        _isWorking.value = true
        try {
            var renewed = client.refresh(refreshToken)
            // Auth0 only returns a new refresh token when rotation is
            // enabled; otherwise the existing one stays valid.
            if (renewed.refreshToken == null) {
                renewed = renewed.copy(refreshToken = refreshToken)
            }
            store(renewed)
            return renewed.accessToken
        } catch (e: Auth0Client.Failure) {
            // Auth0 rejected the refresh token: it is spent or revoked, so
            // the session really is over. A transport error is not this
            // exception type and propagates without signing out.
            signOut()
            throw e
        } finally {
            _isWorking.value = false
        }
    }

    private fun store(tokens: Auth0Tokens) {
        _tokens.value = tokens
        SecureStore.set(context, SecureStore.AUTH0_SESSION, tokens.toJson())
    }

    private fun loadFromStore(): Auth0Tokens? =
        SecureStore.get(context, SecureStore.AUTH0_SESSION)?.let { Auth0Tokens.fromJson(it) }
}
