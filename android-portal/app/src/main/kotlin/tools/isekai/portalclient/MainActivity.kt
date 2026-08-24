package tools.isekai.portalclient

import android.content.Intent
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
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.flow
import kotlinx.coroutines.flow.flowOn
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
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
private const val PROXY_URL = "https://tokyo.link.isekai.tools:8443"
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

class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        handleIfAuthRedirect(intent)
        setContent {
            MaterialTheme {
                Surface(modifier = Modifier.fillMaxSize()) {
                    PortalScreen(keyFile = File(filesDir, "endpoint_key.pem"))
                }
            }
        }
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        handleIfAuthRedirect(intent)
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
fun PortalScreen(keyFile: File) {
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
    var config by remember {
        mutableStateOf(
            PortalConfig(
                identityUrl = IDENTITY_URL,
                proxyUrl = PROXY_URL,
                protocol = PROTOCOL,
                auth0Token = "",
                service = SERVICE,
                expectedEndpoint = "",
                register = register,
            )
        )
    }
    var paired by remember { mutableStateOf(false) }
    var session by remember { mutableStateOf<PortalSession?>(null) }
    var localPort by remember { mutableStateOf<Int?>(null) }
    var status by remember { mutableStateOf("") }
    var statusIsError by remember { mutableStateOf(false) }
    var busy by remember { mutableStateOf(false) }

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
                            askOllamaStream(port, userPrompt, systemPrompt).collect { delta ->
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
                            statusIsError = false
                            // A standing grant now -- no listener id to show;
                            // the server's Endpoint ID is what a restart
                            // cannot invalidate.
                            status = "Paired with ${updated.expectedEndpoint}"
                        } catch (e: Exception) {
                            statusIsError = true
                            status = "Pair failed: ${e.message}"
                        } finally {
                            busy = false
                        }
                    }
                },
                enabled = !busy && canAuthenticate && pairingCode.isNotBlank() && session == null,
            ) { Text("Pair") }

            Button(
                onClick = {
                    status = ""
                    busy = true
                    scope.launch {
                        try {
                            val token = currentAuth0Token()
                            val s = withContext(Dispatchers.IO) {
                                portalConnect(
                                    config = config.copy(auth0Token = token),
                                    endpointKeyPem = endpointKeyPem,
                                )
                            }
                            session = s
                            localPort = s.localPort().toInt()
                            statusIsError = false
                            status = "Connected -- forwarding to \"$SERVICE\" on 127.0.0.1:${localPort}"
                        } catch (e: Exception) {
                            statusIsError = true
                            status = "Connect failed: ${e.message}"
                        } finally {
                            busy = false
                        }
                    }
                },
                enabled = !busy && paired && session == null,
            ) { Text("Connect") }

            Button(
                onClick = {
                    session?.disconnect()
                    session = null
                    localPort = null
                    statusIsError = false
                    status = "Disconnected"
                },
                enabled = session != null,
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
 * Streams Ollama's own `/api/generate` (`stream: true`, the default) through
 * the local port the portal tunnel bound, emitting each response fragment as
 * it arrives rather than blocking for the whole reply. Ollama's streaming
 * wire format is newline-delimited JSON objects, one per fragment, the last
 * one carrying `"done": true`.
 *
 * This replaces the earlier one-shot `stream: false` call, which held the
 * connection completely silent for the full generation time (a minute-plus
 * at this model's speed) -- long enough that the phone's own network stack
 * would give up and tear the connection down before Ollama ever got to send
 * anything back. Streaming keeps real bytes moving the whole time instead.
 */
private fun askOllamaStream(port: Int, prompt: String, systemPrompt: String): Flow<String> = flow {
    val url = URL("http://127.0.0.1:$port/api/generate")
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

    val body = JSONObject()
        .put("model", MODEL)
        .put("prompt", prompt)
        .put("system", systemPrompt)
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
            val fragment = obj.optString("response", "")
            if (fragment.isNotEmpty()) emit(fragment)
            if (obj.optBoolean("done", false)) break
        }
    }
}.flowOn(Dispatchers.IO)
