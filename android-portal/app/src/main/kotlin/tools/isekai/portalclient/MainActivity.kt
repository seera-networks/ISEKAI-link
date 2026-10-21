package tools.isekai.portalclient

import android.content.Intent
import android.net.ConnectivityManager
import android.net.Network
import android.net.Uri
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.foundation.gestures.detectTapGestures
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.compose.ui.input.pointer.pointerInput
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalFocusManager
import androidx.compose.ui.platform.LocalSoftwareKeyboardController
import androidx.compose.ui.unit.dp
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.flow.flow
import kotlinx.coroutines.flow.flowOn
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeoutOrNull
import org.json.JSONArray
import org.json.JSONObject
import uniffi.portal_client_ffi.PortalConfig
import uniffi.portal_client_ffi.PortalSession
import uniffi.portal_client_ffi.connect as portalConnect
import uniffi.portal_client_ffi.endpointIdOf
import uniffi.portal_client_ffi.generateEndpointKeyPem
import uniffi.portal_client_ffi.pairWithCode
import java.io.File
import java.net.HttpURLConnection
import java.net.URL

// Hardcoded for this PoC -- pointed at one known portal-server. No settings
// UI, per the plan's minimal-UI scope.
private const val IDENTITY_URL = "https://identity.isekai.tools:9443"
private const val PROXY_URL = "https://link.isekai.tools:6443"
// Deliberately NOT portal-core's own default ("isekai-portal-v1"): the
// Identity API rejects that protocol string for this account with 403
// protocol-not-allowed (confirmed against a brand-new, never-registered
// Endpoint key too, so it is an account/tenant-level allowlist, not a
// per-Endpoint registration issue). "isekai-validator-v1" is camera-client's
// protocol string, already authorized for this account, and portal-server on
// the Jetson is deliberately started with --protocol isekai-validator-v1 to
// match. Whatever this app uses here MUST match portal-server's --protocol
// flag exactly, or pairing silently succeeds (a Grant is protocol-scoped but
// pairing itself doesn't check reachability) while every subsequent connect
// fails with "nothing reachable" -- hit exactly this after switching this
// constant to "isekai-portal-v1" without updating portal-server's flag to
// match, then again the other way around.
private const val PROTOCOL = "isekai-validator-v1"
private const val SERVICE = "ollama"
private const val MODEL = "qwen3.5:4b"

// How often the active session is asked whether it has closed on its own.
// There is no push notification for this from the Rust side (PortalSession
// exposes a plain poll, see its `isClosed` doc comment) -- short enough that
// a dead session is noticed well inside a person's next "why isn't this
// answering" moment, long enough not to matter next to an FFI call this cheap.
private const val SESSION_HEALTH_POLL_MS = 4_000L

/**
 * How long to wait before trying to reconnect again, by attempt.
 *
 * Capped rather than unbounded: the thing being waited for is usually a
 * network that is already back, and a wait that grows past a few seconds
 * starts to read as "broken" to whoever is holding the phone. The last entry
 * repeats for every attempt after it.
 */
private val RECONNECT_BACKOFF_MS = listOf(1_000L, 2_000L, 4_000L, 8_000L, 15_000L)

/** What one connect attempt leaves behind, for the retry loop to read. */
private enum class Attempt {
    Connected,

    /** Worth another go: a network that was not there, a relay that was busy. */
    Failed,

    /**
     * Not worth another go until a person does something. Only `AuthError`:
     * no token, or one that expired. Retrying that every few seconds would
     * spin forever and bury the one message that says what to do.
     */
    GiveUp,
}

class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        handleIfAuthRedirect(intent)
        setContent {
            MaterialTheme {
                Surface(modifier = Modifier.fillMaxSize()) {
                    val context = LocalContext.current
                    val consent = remember { PrivacyConsentStore(context) }
                    // Over the top, and not dismissable -- using the service
                    // means an account and personal information, so this is
                    // what a new install sees first and the only thing it can
                    // act on. Nothing behind it runs until then: no sign-in,
                    // no Endpoint key, no connect. Same gate as the camera
                    // app's MainActivity.
                    if (consent.needsAgreement) {
                        PrivacyConsentScreen(consent)
                    } else {
                        PortalScreen(
                            keyFile = File(filesDir, "endpoint_key.pem"),
                            pairedFile = File(filesDir, "paired_endpoint"),
                        )
                    }
                }
            }
        }
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        handleIfAuthRedirect(intent)
    }

    /**
     * Catches a Custom Tab dismissed without ever producing a redirect (back
     * button, swipe-away, or Auth0 itself showing an error page instead of
     * redirecting) -- onNewIntent's handleRedirect() never runs in that case,
     * so nothing would otherwise complete Auth0CallbackBroker's deferred and
     * AuthStore.signIn() would suspend forever (isekai-link#178). Android
     * always delivers a redirect's onNewIntent before this onResume for the
     * same foreground transition, so by the time this runs, a completed
     * broker has already cleared `pending` and this is a no-op; only a
     * still-pending one -- meaning no redirect arrived -- gets cancelled.
     */
    override fun onResume() {
        super.onResume()
        Auth0CallbackBroker.cancelPending()
    }

    /**
     * The Auth0 redirect lands here as a `VIEW` intent (see the intent-filter
     * in AndroidManifest.xml) because `singleTop` keeps this Activity from
     * being recreated -- Android delivers it to the already-running instance
     * via `onNewIntent` rather than `onCreate` in the common case. Handling
     * both anyway covers the app being killed while the Custom Tab was open.
     * Mirrors `cameraclient.MainActivity`'s own version of this exactly.
     */
    private fun handleIfAuthRedirect(intent: Intent?) {
        val uri: Uri = intent?.data ?: return
        if (uri.scheme == Auth0Config.CALLBACK_SCHEME) {
            Auth0CallbackBroker.handleRedirect(uri)
        }
    }
}

@Composable
fun PortalScreen(keyFile: File, pairedFile: File) {
    val scope = rememberCoroutineScope()
    val context = LocalContext.current
    val authStore = remember { AuthStore(context.applicationContext) }

    // Endpoint key: generated once, persisted in plain internal storage
    // (encryption is a nice-to-have this PoC skips, per the plan). `register`
    // is true only for the launch that actually generates a fresh key.
    var register by remember { mutableStateOf(false) }
    var endpointKeyPem by remember {
        mutableStateOf(
            if (keyFile.exists()) {
                keyFile.readText()
            } else {
                val pem = generateEndpointKeyPem()
                keyFile.writeText(pem)
                register = true
                pem
            }
        )
    }
    var endpointId by remember { mutableStateOf(runCatching { endpointIdOf(endpointKeyPem) }.getOrDefault("")) }

    val authTokens by authStore.tokens.collectAsState()
    val authWorking by authStore.isWorking.collectAsState()
    var authError by remember { mutableStateOf<String?>(null) }
    // The manual-paste field: a fallback for when Auth0 itself is
    // unreachable, same role as cameraclient's own "fallback" token field --
    // only consulted when not signed in, never persisted.
    var manualToken by remember { mutableStateOf("") }

    var pairingCode by remember { mutableStateOf("") }

    /**
     * The Endpoint this key is paired with, remembered across launches.
     *
     * **A Grant survives a restart; this is what it takes for the app to act
     * like it.** Pairing produces a standing Grant held by the control plane,
     * keyed on `(server, client, protocol)` with no listener id — which is
     * exactly why `portal-server` can restart without anyone re-pairing. The
     * app had no record of it: `config.expectedEndpoint` started empty and
     * `paired` started false on every launch, so Connect was disabled and the
     * only way forward was to pair again, for a Grant already held. The
     * comment on the pairing success path has said "the server's Endpoint ID
     * is what a restart cannot invalidate" the whole time; the value was
     * being thrown away one launch later.
     *
     * Plain internal storage beside `endpoint_key.pem`, not `SecureStore`:
     * the peer's Endpoint ID is an identifier, not a credential — the app
     * prints its own on screen — and `SecureStore` is scoped to the Auth0
     * session on purpose. The Grant itself is not here to be stolen; it lives
     * with the control plane and is bound to the key next to this file.
     */
    val pairedEndpoint = remember {
        runCatching { if (pairedFile.exists()) pairedFile.readText().trim() else "" }
            .getOrDefault("")
    }
    var config by remember {
        mutableStateOf(
            PortalConfig(
                identityUrl = IDENTITY_URL,
                proxyUrl = PROXY_URL,
                protocol = PROTOCOL,
                auth0Token = "",
                service = SERVICE,
                expectedEndpoint = pairedEndpoint,
                register = register,
            )
        )
    }
    var paired by remember { mutableStateOf(pairedEndpoint.isNotEmpty()) }
    var session by remember { mutableStateOf<PortalSession?>(null) }
    var localPort by remember { mutableStateOf<Int?>(null) }
    // Says who the remembered pairing is with, at launch. Without it the only
    // visible difference a restored pairing makes is that Connect is enabled,
    // and a *stale* one -- `portal-server` reinstalled with a new key -- looks
    // identical to a good one until the connect fails. Naming the Endpoint is
    // what makes "this is not the server I am looking at" something a person
    // can notice, and re-pairing the obvious next move.
    var status by remember {
        mutableStateOf(if (pairedEndpoint.isEmpty()) "" else "Paired with $pairedEndpoint")
    }
    var statusIsError by remember { mutableStateOf(false) }
    var busy by remember { mutableStateOf(false) }

    /**
     * Whether a session is wanted — true from Connect until Disconnect.
     *
     * **This is the intent `session == null` used to stand in for**, and the
     * substitution is the bug: a reconnect that has just failed leaves
     * `session` null too, so the one event that could have retried declined to.
     */
    var wanted by remember { mutableStateOf(false) }

    /**
     * Bumped whenever something happens that makes retrying worth doing now —
     * a network arriving, or Connect being tapped while a retry is waiting.
     * A retry sitting in its backoff watches this and stops waiting.
     */
    var wakeRetry by remember { mutableStateOf(0) }

    /**
     * Whether a connect attempt is in flight.
     *
     * Separate from `busy`, which Pair and Send also use: see
     * `connectSession`. Deliberately **not** what Disconnect is gated on —
     * stopping has to stay available while an attempt is running, or the only
     * way out of a retry is to kill the app.
     */
    var connecting by remember { mutableStateOf(false) }

    var prompt by remember { mutableStateOf("") }
    var chatLog by remember { mutableStateOf(listOf<Pair<String, String>>()) } // (who, text)

    // Sent as Ollama's "system" field on every request -- see
    // assets/system_prompt.md for the instruction itself. Loaded once and
    // reused rather than per-request: it's static for the life of the app.
    val systemPrompt = remember {
        context.assets.open("system_prompt.md").bufferedReader().use { it.readText() }
    }

    // Resolves the token to use for the next Pair/Connect call: a real,
    // auto-refreshed Auth0 session when signed in, the manual-paste fallback
    // otherwise. Suspend because a stale access token means a live refresh
    // call first (see AuthStore.accessToken).
    suspend fun currentAuth0Token(): String =
        if (authStore.isSignedIn) {
            authStore.accessToken()
        } else {
            manualToken.trim().also {
                if (it.isEmpty()) throw AuthError.NotSignedIn
            }
        }

    val canAuthenticate = authStore.isSignedIn || manualToken.isNotBlank()

    val focusManager = LocalFocusManager.current
    val keyboardController = LocalSoftwareKeyboardController.current

    // Shared by the Connect button and the network-change auto-reconnect
    // below -- both need the exact same "get a token, call connect(), record
    // the session" sequence, and having two copies is how they'd drift.
    // `reason` only changes what's shown on failure, so a dropped network
    // mid-reconnect doesn't read as if the button itself failed.
    suspend fun connectSession(reason: String): Attempt {
        // **Its own flag, not `busy`.** `busy` is shared with Pair and Send,
        // and a Send stream can run for a minute. If the redialer cleared it
        // on the way out, the prompt would come back live while the first
        // stream was still collecting, and two concurrent `Send`s both edit
        // the last `chatLog` entry -- they would interleave into one line and
        // clobber each other's tokens.
        connecting = true
        try {
            val token = currentAuth0Token()
            val stored = authStore.tokens.value
            val s = withContext(Dispatchers.IO) {
                portalConnect(
                    config = config.copy(auth0Token = token),
                    endpointKeyPem = endpointKeyPem,
                    refreshToken = stored?.refreshToken,
                    accessTokenExpiresAtUnix = ((stored?.expiresAt ?: 0L) / 1000).toULong(),
                )
            }
            if (!wanted) {
                // Stopped while this was in flight. `portalConnect` is a
                // blocking FFI call that cancellation cannot interrupt, so by
                // the time anyone could say stop it has already built a live
                // session -- adopting it would reconnect somebody who just
                // asked not to be. `NonCancellable` because this coroutine is
                // very likely already cancelled, and a session dropped without
                // `disconnect()` leaves the tunnel up on the far side.
                withContext(NonCancellable + Dispatchers.IO) { s.disconnect() }
                return Attempt.Failed
            }
            session = s
            localPort = s.localPort().toInt()
            statusIsError = false
            status = "Connected -- forwarding to \"$SERVICE\" on 127.0.0.1:${localPort}"
            return Attempt.Connected
        } catch (e: CancellationException) {
            // Not a failure of the connect, and not the retry loop's business:
            // caught by the generic clause below it would be written to the
            // status and classified as worth another go, which is a lie about
            // what happened.
            throw e
        } catch (e: AuthError) {
            // Nothing out here will fix this one, so the retry stops and the
            // message stays put instead of being overwritten every few seconds.
            statusIsError = true
            status = "$reason failed: ${e.message}"
            return Attempt.GiveUp
        } catch (e: Exception) {
            statusIsError = true
            status = "$reason failed: ${e.message}"
            return Attempt.Failed
        } finally {
            connecting = false
        }
    }

    // **One place redials, and it keeps trying.**
    //
    // What this replaces: two separate paths each called `connectSession`
    // exactly once and gave up if it failed, and the network-change callback
    // then declined to help because it tested `session == null` -- which is
    // just as true after a failed reconnect as after a deliberate Disconnect.
    // So a Wi-Fi -> cellular switch *with a gap in the middle* -- the phone on
    // no usable network for a few seconds, the ordinary shape of a handover --
    // left the app sitting on "Reconnect failed" with a working network and
    // nothing retrying. Measured on an emulator: 87 seconds in, still stuck,
    // ping to the control plane fine, and one tap of Connect fixed it
    // instantly. A switch with no gap recovered on its own, which is why the
    // demo and every casual test looked right.
    //
    // `wanted` is the intent that `session == null` was standing in for, and
    // the two callbacks below now only ever *clear* a session. Having one
    // redialer also retires the `busy` dance the two of them needed, which was
    // a race rather than a fix.
    LaunchedEffect(wanted, session) {
        if (!wanted || session != null) return@LaunchedEffect
        var attempt = 0
        while (isActive && wanted && session == null) {
            // **Read before the attempt, not after.** A wake that lands while
            // the attempt is in flight is the important one: the attempt was
            // begun with no network and is doomed, and the network arriving
            // mid-flight is exactly the news worth acting on. Sampling after
            // it returns folds that wake into the baseline and sleeps out the
            // whole backoff with a working network -- the symptom this change
            // exists to remove, just time-boxed.
            val waking = wakeRetry
            val outcome = connectSession(if (attempt == 0) "Connect" else "Reconnect")
            if (outcome == Attempt.Connected) break
            // Kept, because the countdown below is about to overwrite it in
            // this same continuation -- so without this the failure never
            // reaches a frame, and a connect that keeps failing shows nothing
            // but a timer.
            val why = status
            attempt++
            if (outcome == Attempt.GiveUp) {
                // **Waits instead of returning.** Breaking out would leave this
                // effect finished with `wanted` still true and `session` still
                // null -- neither key changes when Connect is tapped, so the
                // effect would never restart and the button would do nothing.
                // Waiting here keeps the one thing that redials alive and lets
                // a tap, or a network arriving after a sign-in, start it again.
                // The auth message stays on screen until then.
                snapshotFlow { wakeRetry }.first { it != waking }
                attempt = 0
                continue
            }
            val wait = RECONNECT_BACKOFF_MS[
                minOf(attempt - 1, RECONNECT_BACKOFF_MS.lastIndex)
            ]
            statusIsError = false
            status = "Reconnecting in ${wait / 1000}s... ($why)"
            // A network arriving is reason to stop waiting -- that wait is the
            // only thing left between a returning network and a working tunnel.
            // Raced against the delay rather than cancelling this effect on it:
            // a connect in flight is a blocking FFI call that cancellation
            // cannot actually stop, so a cancelled one would run to completion
            // and drop its session without disconnecting it.
            withTimeoutOrNull(wait) {
                snapshotFlow { wakeRetry }.first { it != waking }
            }
        }
    }

    // **A token arriving is a wake.** `connectSession` parks the redialer on
    // an `AuthError` rather than returning, precisely so a sign-in can start
    // it again -- but nothing was telling it one had happened, so the park
    // only ever ended on a tap or a network change.
    //
    // **Keyed on the tokens, not on `canAuthenticate`.** That boolean is an
    // OR, and the case this exists for hides inside it: with a token left in
    // the fallback field *and* an Auth0 session, an access token that expires
    // with no refresh token (this app asks for no `offline_access`, so that
    // is the ordinary ending) makes `AuthStore` sign out and throw
    // `SessionExpired`. The redialer parks -- and `canAuthenticate` never
    // moved, because the stale manual token still counts. Signing in again
    // would not move it either, so the one event this is here to notice would
    // be the one it slept through. `manualToken` by its blankness rather than
    // its text, or every keystroke while pasting a token would cut a backoff
    // short.
    LaunchedEffect(authTokens, manualToken.isNotBlank()) {
        if (canAuthenticate) wakeRetry++
    }

    // Notice when the OS moves the default network out from under a session
    // (Wi-Fi <-> cellular). The underlying QUIC connection does not survive
    // that on its own: the local socket a session opened dies with the network
    // it was on, and nothing today makes the session migrate -- so without
    // this, the UI sits on a stale "Connected" long after the tunnel is dead,
    // and the first sign anything is wrong is the next send failing with
    // "Failed to connect to /127.0.0.1:<port>" (#211). Handled here rather
    // than deeper in the Rust core because noticing a network change is
    // Android's job to report and the app's to act on -- and a plain redial is
    // enough because pairing produced a standing grant, not a one-shot
    // capability.
    DisposableEffect(Unit) {
        val connectivityManager = context.getSystemService(ConnectivityManager::class.java)
        // Plain var, not Compose state: this is bookkeeping the callback
        // itself owns, and giving it to Compose would trigger a recomposition
        // for every network blip whether or not a session cared.
        var lastNetwork: Network? = null
        val callback = object : ConnectivityManager.NetworkCallback() {
            override fun onAvailable(network: Network) {
                val previous = lastNetwork
                lastNetwork = network
                // On the main thread, because everything it touches is Compose
                // state and this runs on a callback thread of the framework's
                // choosing.
                scope.launch {
                    // **Unconditionally**, before any of the tests below: a
                    // retry waiting out its backoff needs to hear that the
                    // ground moved even -- especially -- when there is no
                    // session left to replace.
                    wakeRetry++
                    // The very first call just reports the network already in
                    // use when the callback registers; nothing to recover from.
                    if (previous == null || previous == network) return@launch
                    val old = session ?: return@launch
                    statusIsError = false
                    status = "Network changed -- reconnecting..."
                    session = null
                    localPort = null
                    // Best-effort: the old session's transport is almost
                    // certainly already dead on the network that just went
                    // away, so this is tidying up local state, not something a
                    // failure here should block the reconnect on. Clearing
                    // `session` above is what starts the redial.
                    runCatching { withContext(Dispatchers.IO) { old.disconnect() } }
                }
            }
        }
        connectivityManager?.registerDefaultNetworkCallback(callback)
        onDispose { connectivityManager?.unregisterNetworkCallback(callback) }
    }

    // Notice a session that died for any *other* reason than a network change:
    // a relay leg the control plane moved elsewhere, or a direct path that
    // stalls with no working relay behind it (#212). Keyed on `session` itself,
    // so a new session restarts this for it and clearing one stops it.
    LaunchedEffect(session) {
        val watched = session ?: return@LaunchedEffect
        while (isActive) {
            delay(SESSION_HEALTH_POLL_MS)
            if (!watched.isClosed()) continue
            // Clearing it is the whole job here -- the redialer above owns
            // trying again. `===` because by now `session` may already be a
            // newer one, and clearing that would disconnect something live.
            // `wanted` as well as the identity check: Disconnect sets `wanted`
            // false and only clears `session` once `disconnect()` returns,
            // which takes a few seconds, and a tick inside that window would
            // announce "Session ended -- reconnecting..." about a session the
            // person deliberately tore down.
            if (wanted && session === watched) {
                statusIsError = false
                status = "Session ended -- reconnecting..."
                session = null
                localPort = null
            }
            break
        }
    }

    Column(
        modifier = Modifier
            .fillMaxSize()
            // Tap anywhere outside a field to drop focus and hide the
            // keyboard. This Activity has no back stack (singleTop, one
            // Activity total), so BACK is not a safe way to dismiss the
            // keyboard here -- it can finish() the Activity instead, and
            // that can happen on a delay that makes it look like a later,
            // unrelated tap caused the app to exit.
            .pointerInput(Unit) {
                detectTapGestures(onTap = {
                    focusManager.clearFocus()
                    keyboardController?.hide()
                })
            }
            .verticalScroll(rememberScrollState())
            .padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        Text("Portal Client", style = MaterialTheme.typography.headlineSmall)
        Text("Endpoint ID: $endpointId", style = MaterialTheme.typography.bodySmall)

        // --- Chat --------------------------------------------------------
        Text("Chat (via Ollama, tunneled over the P2P portal)", style = MaterialTheme.typography.titleMedium)

        for ((who, text) in chatLog) {
            Text(
                "$who: $text",
                style = MaterialTheme.typography.bodySmall,
                color = if (who == "error") MaterialTheme.colorScheme.error else MaterialTheme.colorScheme.onSurface,
            )
        }

        Row(horizontalArrangement = Arrangement.spacedBy(12.dp)) {
            OutlinedTextField(
                value = prompt,
                onValueChange = { prompt = it },
                label = { Text("Prompt") },
                modifier = Modifier.weight(1f),
                singleLine = true,
                enabled = localPort != null && !busy,
            )
            Button(
                onClick = {
                    val port = localPort ?: return@Button
                    val userPrompt = prompt
                    // Captured before this turn's placeholder entries go in --
                    // this is what makes Ollama remember earlier turns at all
                    // (see askOllamaChatStream: it's resent as /api/chat's
                    // `messages` array every time, since Ollama itself keeps
                    // no state between requests).
                    val history = chatLog
                    // A placeholder "ollama" entry that gets filled in as tokens
                    // stream back, instead of one entry appended only once the
                    // whole response is done -- this is also what avoids the
                    // long-silent-wait issue that killed non-streamed replies:
                    // stream:true means real bytes keep crossing the tunnel the
                    // whole time, rather than sitting quiet for a minute-plus.
                    chatLog = chatLog + ("you" to userPrompt) + ("ollama" to "")
                    prompt = ""
                    busy = true
                    scope.launch {
                        try {
                            askOllamaChatStream(port, history, userPrompt, systemPrompt).collect { delta ->
                                val last = chatLog.last()
                                chatLog = chatLog.dropLast(1) + (last.first to last.second + delta)
                            }
                        } catch (e: Exception) {
                            val last = chatLog.last()
                            val soFar = if (last.first == "ollama") last.second else ""
                            chatLog = chatLog.dropLast(1) + ("ollama" to soFar) + ("error" to (e.message ?: e.toString()))
                        } finally {
                            busy = false
                        }
                    }
                },
                enabled = localPort != null && !busy && prompt.isNotBlank(),
            ) { Text("Send") }
        }

        HorizontalDivider()

        // --- Account (Auth0) ---------------------------------------------
        Text("Account", style = MaterialTheme.typography.titleMedium)
        if (authTokens != null) {
            Text("Signed in with Auth0.", style = MaterialTheme.typography.bodySmall)
            Button(onClick = { authStore.signOut() }) { Text("Sign out") }
        } else {
            Button(
                onClick = {
                    authError = null
                    scope.launch {
                        try {
                            authStore.signIn()
                        } catch (e: Exception) {
                            authError = e.message
                        }
                    }
                },
                enabled = !authWorking,
            ) { Text(if (authWorking) "Signing in…" else "Sign in with Auth0") }
            LabeledField("Auth0 access token (fallback, only used when not signed in)", manualToken) {
                manualToken = it
            }
            authError?.let {
                Text(it, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.error)
            }
        }

        LabeledField("Pairing code", pairingCode, enabled = session == null) { pairingCode = it }

        Row(horizontalArrangement = Arrangement.spacedBy(12.dp)) {
            Button(
                onClick = {
                    status = ""
                    busy = true
                    scope.launch {
                        try {
                            val token = currentAuth0Token()
                            val updated = withContext(Dispatchers.IO) {
                                pairWithCode(
                                    config = config.copy(auth0Token = token, register = register),
                                    endpointKeyPem = endpointKeyPem,
                                    code = pairingCode.trim(),
                                )
                            }
                            config = updated
                            register = false
                            paired = true
                            // **Re-pairing is the documented recovery from a
                            // stale pairing, so make it land.** The redialer
                            // may be mid-backoff against the Endpoint that
                            // just got replaced; without this it waits out the
                            // rest of it and then tries the old config once
                            // more, and the "Paired with ..." below is
                            // overwritten by its countdown within a second --
                            // so a re-pair that worked reads on screen as a
                            // continuing failure.
                            wakeRetry++
                            // Written here rather than at connect time: this
                            // is the one moment the Endpoint ID is known to
                            // be the one a Grant was just made for.
                            //
                            // A failure is said out loud rather than
                            // swallowed. The Grant is real either way -- it is
                            // the control plane's, not this file's -- but a
                            // silent failure would promise that the next
                            // launch remembers, and then quietly want a
                            // pairing code again with nothing explaining why.
                            val kept = runCatching {
                                pairedFile.writeText(updated.expectedEndpoint)
                            }.isSuccess
                            if (!kept) {
                                // `writeText` truncates when it opens, so a
                                // failure part-way through leaves an empty
                                // file and the message below is true. A
                                // failure to open at all leaves the *previous*
                                // Endpoint sitting there -- so the next launch
                                // would restore a pairing this one replaced,
                                // name it on screen, and offer Connect against
                                // a server that may no longer exist. Remove it
                                // rather than let the message be a lie.
                                runCatching { pairedFile.delete() }
                            }
                            statusIsError = false
                            // A standing grant now -- no listener id to show;
                            // the server's Endpoint ID is what a restart
                            // cannot invalidate.
                            status = "Paired with ${updated.expectedEndpoint}" +
                                if (kept) "" else " (could not be saved -- this app will ask to pair again next launch)"
                        } catch (e: Exception) {
                            statusIsError = true
                            status = "Pair failed: ${e.message}"
                        } finally {
                            busy = false
                        }
                    }
                },
                enabled = !busy && !connecting && canAuthenticate &&
                    pairingCode.isNotBlank() && session == null,
            ) { Text("Pair") }

            Button(
                onClick = {
                    status = ""
                    // Says what is wanted; the redialer above does it. Waking
                    // it too, so tapping Connect during a backoff tries now
                    // rather than waiting the rest of it out -- and so the tap
                    // does something visible even when `wanted` was already
                    // true.
                    wanted = true
                    wakeRetry++
                },
                // **`canAuthenticate` is new here, and it is not new in
                // spirit.** `paired` could previously only become true by way
                // of a successful Pair, which is gated on it -- so Connect was
                // unreachable while signed out without anyone saying so. A
                // remembered pairing removes that accident: without this the
                // button would be live on a signed-out launch, spend an
                // attempt, and park on an auth error.
                enabled = !busy && !connecting && paired && canAuthenticate &&
                    session == null,
            ) { Text("Connect") }

            Button(
                onClick = {
                    // **Before anything else.** This is the one thing that
                    // stops the redialer, and it has to be false before
                    // `session` goes null or it would read that as a session
                    // to recover.
                    wanted = false
                    status = ""
                    val s = session
                    if (s == null) {
                        // Retrying rather than connected. There is nothing to
                        // tear down; clearing `wanted` above is the whole of
                        // it, and saying so is what tells the person it
                        // stopped.
                        statusIsError = false
                        status = "Disconnected"
                        return@Button
                    }
                    busy = true
                    scope.launch {
                        // disconnect() now waits (bounded, up to a few
                        // seconds) for the tunnel to actually report itself
                        // torn down, not just for the cancel signal to be
                        // sent -- run it off the main thread like every other
                        // FFI call here, or this would freeze the UI for that
                        // whole wait.
                        withContext(Dispatchers.IO) { s.disconnect() }
                        session = null
                        localPort = null
                        statusIsError = false
                        status = "Disconnected"
                        busy = false
                    }
                },
                // **`wanted` too, and not gated on `connecting`.** While the
                // redialer is retrying there is no session, so gating on one
                // left the only way to stop it being to kill the app.
                enabled = (session != null || wanted) && !busy,
            ) { Text("Disconnect") }
        }

        if (status.isNotBlank()) {
            Text(
                status,
                style = MaterialTheme.typography.bodySmall,
                color = if (statusIsError) MaterialTheme.colorScheme.error else MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
    }
}

/** Mirrors cameraclient's `LabeledField`, for the same consistent field look. */
@Composable
private fun LabeledField(
    label: String,
    value: String,
    enabled: Boolean = true,
    onValueChange: (String) -> Unit,
) {
    OutlinedTextField(
        value = value,
        onValueChange = onValueChange,
        label = { Text(label) },
        modifier = Modifier.fillMaxWidth(),
        singleLine = true,
        enabled = enabled,
    )
}

/**
 * Streams Ollama's `/api/chat` (`stream: true`, the default) through the
 * local port the portal tunnel bound, emitting each response fragment as it
 * arrives rather than blocking for the whole reply. Ollama's streaming wire
 * format is newline-delimited JSON objects, one per fragment, the last one
 * carrying `"done": true`.
 *
 * `/api/chat` rather than `/api/generate`: Ollama itself keeps no state
 * between requests either way, so multi-turn memory only exists if the
 * client resends the conversation -- `history` (everything in `chatLog`
 * before this turn) is what makes that happen, translated into `/api/chat`'s
 * `messages` array (`"you"` -> `role: "user"`, `"ollama"` -> `role:
 * "assistant"`; `"error"` entries are skipped, they're not real conversation
 * content). Before this, every request sent only the current turn's text --
 * qwen had nothing to remember because nothing prior was ever sent to it.
 *
 * Streaming itself (vs. the one-shot `stream: false` this replaced first)
 * is what avoids the long-silent-wait issue that killed non-streamed
 * replies: real bytes keep crossing the tunnel the whole time generation
 * runs, rather than sitting quiet for a minute-plus.
 */
private fun askOllamaChatStream(
    port: Int,
    history: List<Pair<String, String>>,
    prompt: String,
    systemPrompt: String,
): Flow<String> = flow {
    val url = URL("http://127.0.0.1:$port/api/chat")
    val conn = url.openConnection() as HttpURLConnection
    conn.requestMethod = "POST"
    conn.doOutput = true
    conn.setRequestProperty("Content-Type", "application/json")
    conn.connectTimeout = 10_000
    // Per-read timeout, not for the whole reply -- each fragment arrives every
    // couple hundred ms at this model's token rate once the model is loaded,
    // so this only trips if a single fragment goes missing. Set high enough
    // to also cover the *first* fragment after Ollama has to cold-load the
    // model from scratch (idle timeout, a restart, or -- on this Jetson --
    // every time it was stopped to free memory for a build): that alone
    // measured ~38s once, and a client that gives up before it finishes
    // makes Ollama abort the load server-side too, so the failure is total,
    // not partial.
    conn.readTimeout = 90_000

    val messages = JSONArray()
        .put(JSONObject().put("role", "system").put("content", systemPrompt))
    for ((who, text) in history) {
        val role = when (who) {
            "you" -> "user"
            "ollama" -> "assistant"
            else -> continue // "error" entries: not real conversation content
        }
        messages.put(JSONObject().put("role", role).put("content", text))
    }
    messages.put(JSONObject().put("role", "user").put("content", prompt))

    val body = JSONObject()
        .put("model", MODEL)
        .put("messages", messages)
        .put("stream", true)
        .put("think", false)
        .put("options", JSONObject().put("num_predict", 500))
        .toString()
    conn.outputStream.use { it.write(body.toByteArray(Charsets.UTF_8)) }

    val code = conn.responseCode
    if (code !in 200..299) {
        val text = conn.errorStream?.bufferedReader()?.use { it.readText() } ?: ""
        throw RuntimeException("HTTP $code: $text")
    }

    conn.inputStream.bufferedReader().useLines { lines ->
        for (line in lines) {
            if (line.isBlank()) continue
            val obj = JSONObject(line)
            val fragment = obj.optJSONObject("message")?.optString("content", "") ?: ""
            if (fragment.isNotEmpty()) emit(fragment)
            if (obj.optBoolean("done", false)) break
        }
    }
}.flowOn(Dispatchers.IO)
