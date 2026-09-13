package tools.isekai.cameraclient

import android.content.pm.PackageManager
import android.net.Uri
import android.os.Bundle
import android.content.Intent
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.result.contract.ActivityResultContracts
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.aspectRatio
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.Checkbox
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.dp
import androidx.core.content.ContextCompat
import androidx.lifecycle.viewmodel.compose.viewModel
import uniffi.isekai_client_ffi.PathInfo

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
                    // act on. Mirrors iOS's own `fullScreenCover` gate in
                    // `IsekaiCameraClientApp.swift`.
                    if (consent.needsAgreement) {
                        PrivacyConsentScreen(consent)
                    } else {
                        ViewerScreen()
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
     */
    private fun handleIfAuthRedirect(intent: Intent?) {
        val uri: Uri = intent?.data ?: return
        if (uri.scheme == Auth0Config.CALLBACK_SCHEME) {
            Auth0CallbackBroker.handleRedirect(uri)
        }
    }
}

@Composable
private fun ViewerScreen(model: ViewerModel = viewModel()) {
    val uiState by model.uiState.collectAsState()
    val settings by model.settings.collectAsState()
    val manualToken by model.manualToken.collectAsState()
    val authTokens by model.auth.tokens.collectAsState()
    val authWorking by model.auth.isWorking.collectAsState()
    val cameras by model.cameras.collectAsState()
    val cameraStatus by model.cameraStatus.collectAsState()
    val isBusyWithCameras by model.isBusyWithCameras.collectAsState()

    val context = LocalContext.current
    var showScanner by remember { mutableStateOf(false) }
    var pairingCodeInput by remember { mutableStateOf("") }

    val cameraPermission =
        rememberLauncherForActivityResult(ActivityResultContracts.RequestPermission()) { granted ->
            if (granted) showScanner = true
        }

    if (showScanner) {
        QrScanScreen(
            onCode = { code ->
                showScanner = false
                model.pair(code)
            },
            onCancel = { showScanner = false },
        )
        return
    }

    Column(
        modifier =
            Modifier
                .fillMaxSize()
                .verticalScroll(rememberScrollState())
                .padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        Text("Isekai Camera Client", style = MaterialTheme.typography.headlineSmall)

        // --- Video -----------------------------------------------------
        Box(
            modifier =
                Modifier
                    .fillMaxWidth()
                    .aspectRatio(4f / 3f)
                    .background(Color.Black),
            contentAlignment = Alignment.Center,
        ) {
            val frame = uiState.frame
            if (frame != null) {
                Image(
                    bitmap = frame.asImageBitmap(),
                    contentDescription = "Live video",
                    modifier = Modifier.fillMaxSize(),
                )
            } else {
                Text("No video", color = Color.White)
            }
        }

        // --- Status ------------------------------------------------------
        Text("Status: ${uiState.statusText}", style = MaterialTheme.typography.bodyLarge)
        if (uiState.statusDetail.isNotEmpty()) {
            Text(uiState.statusDetail, style = MaterialTheme.typography.bodySmall)
        }
        Text("Frames received: ${uiState.frameCount}", style = MaterialTheme.typography.bodySmall)
        Text("Endpoint ID: ${uiState.endpointId}", style = MaterialTheme.typography.bodySmall)
        if (uiState.connectionId.isNotEmpty()) {
            Text("Connection ID: ${uiState.connectionId}", style = MaterialTheme.typography.bodySmall)
        }

        // --- Path (relay vs. direct) --------------------------------------
        // Both entries are live once both are known; `onRelay` says where the
        // traffic actually is, not just which paths exist. Mirrors iOS's
        // `streamSection` path rows and its "Switch to..." button.
        uiState.paths?.let { paths ->
            PathRow(label = "Isekai Link", path = paths.relay, active = paths.onRelay)
            PathRow(label = "Direct", path = paths.direct, active = !paths.onRelay)
            Button(onClick = { model.migrate() }, enabled = paths.canMigrate) {
                Text(if (paths.onRelay) "Switch to direct path" else "Switch to Isekai Link")
            }
        }

        uiState.errorMessage?.let {
            Text(it, color = MaterialTheme.colorScheme.error, style = MaterialTheme.typography.bodySmall)
        }

        val connected =
            uiState.phase == Phase.CONNECTING ||
                uiState.phase == Phase.CONNECTED ||
                uiState.phase == Phase.STREAMING ||
                uiState.phase == Phase.RECONNECTING
        Row(horizontalArrangement = Arrangement.spacedBy(12.dp)) {
            Button(onClick = { model.connect() }, enabled = !connected) {
                Text("Connect")
            }
            Button(onClick = { model.disconnect() }, enabled = connected) {
                Text("Disconnect")
            }
        }
        Button(onClick = { model.resetEndpointKey() }, enabled = !connected) {
            Text("Reset Endpoint key")
        }

        // --- Account (Auth0) ---------------------------------------------
        Text("Account", style = MaterialTheme.typography.titleMedium)
        if (authTokens != null) {
            Text("Signed in with Auth0.", style = MaterialTheme.typography.bodySmall)
            Button(onClick = { model.signOut() }) { Text("Sign out") }
        } else {
            Button(onClick = { model.signIn() }, enabled = !authWorking) {
                Text(if (authWorking) "Signing in…" else "Sign in with Auth0")
            }
            LabeledField("Auth0 access token (fallback, only used when not signed in)", manualToken) {
                model.updateManualToken(it)
            }
        }

        // --- Cameras -------------------------------------------------------
        Text("Cameras", style = MaterialTheme.typography.titleMedium)
        when {
            cameras == null -> Text("Not read yet", color = MaterialTheme.colorScheme.onSurfaceVariant)
            cameras!!.isEmpty() -> Text("None — pair with a camera below.", color = MaterialTheme.colorScheme.onSurfaceVariant)
            else ->
                Column {
                    cameras!!.forEach { camera ->
                        Row(
                            modifier =
                                Modifier
                                    .fillMaxWidth()
                                    .padding(vertical = 4.dp),
                            horizontalArrangement = Arrangement.SpaceBetween,
                        ) {
                            Text(camera.label)
                            Button(onClick = { model.selectCamera(camera) }, enabled = !isBusyWithCameras) {
                                Text("Select")
                            }
                        }
                    }
                }
        }
        cameraStatus?.let { Text(it, style = MaterialTheme.typography.bodySmall) }
        Button(onClick = { model.refreshCameras() }, enabled = !isBusyWithCameras) {
            Text("Refresh cameras")
        }
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            OutlinedTextField(
                value = pairingCodeInput,
                onValueChange = { pairingCodeInput = it },
                label = { Text("Pairing code") },
                singleLine = true,
                modifier = Modifier.weight(1f),
            )
            Button(
                onClick = { model.pair(pairingCodeInput); pairingCodeInput = "" },
                enabled = !isBusyWithCameras && pairingCodeInput.isNotBlank(),
            ) {
                Text("Pair")
            }
        }
        Button(
            onClick = {
                val hasPermission =
                    ContextCompat.checkSelfPermission(context, android.Manifest.permission.CAMERA) ==
                        PackageManager.PERMISSION_GRANTED
                if (hasPermission) {
                    showScanner = true
                } else {
                    cameraPermission.launch(android.Manifest.permission.CAMERA)
                }
            },
            enabled = !isBusyWithCameras,
        ) {
            Text("Scan QR code")
        }

        // --- Server settings ----------------------------------------------
        Text("Server", style = MaterialTheme.typography.titleMedium)
        LabeledField("Identity URL", settings.identityUrl) { model.updateSettings { s -> s.copy(identityUrl = it) } }
        LabeledField("Proxy URL", settings.proxyUrl) { model.updateSettings { s -> s.copy(proxyUrl = it) } }
        LabeledField("Protocol", settings.protocolName) { model.updateSettings { s -> s.copy(protocolName = it) } }
        LabeledField("Capability", settings.capability) { model.updateSettings { s -> s.copy(capability = it) } }
        LabeledField("Listener ID", settings.listenerId) { model.enterListenerByHand(it) }
        CheckedRow("Register endpoint", settings.register) { model.updateSettings { s -> s.copy(register = it) } }

        // --- Development ----------------------------------------------
        Text("Development", style = MaterialTheme.typography.titleMedium)
        CheckedRow("Skip TLS verification", settings.insecureSkipVerify) {
            model.updateSettings { s -> s.copy(insecureSkipVerify = it) }
        }
        CheckedRow("Direct path", settings.enableMigration) { model.updateSettings { s -> s.copy(enableMigration = it) } }
        LabeledField("Log filter (RUST_LOG syntax)", settings.logFilter) {
            model.updateSettings { s -> s.copy(logFilter = it) }
        }
    }
}

@Composable
private fun LabeledField(
    label: String,
    value: String,
    onValueChange: (String) -> Unit,
) {
    OutlinedTextField(
        value = value,
        onValueChange = onValueChange,
        label = { Text(label) },
        modifier = Modifier.fillMaxWidth(),
        singleLine = true,
    )
}

/** One end-to-end route the video can take. Mirrors iOS's `PathRow`. */
@Composable
private fun PathRow(
    label: String,
    path: PathInfo?,
    active: Boolean,
) {
    Row(
        modifier = Modifier.fillMaxWidth(),
        horizontalArrangement = Arrangement.SpaceBetween,
    ) {
        Text(if (active) "▶ $label" else label, style = MaterialTheme.typography.bodySmall)
        Text(
            path?.let { "${it.local} → ${it.remote}" } ?: "not available",
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
    }
}

@Composable
private fun CheckedRow(
    label: String,
    checked: Boolean,
    onCheckedChange: (Boolean) -> Unit,
) {
    Row(verticalAlignment = Alignment.CenterVertically) {
        Checkbox(checked = checked, onCheckedChange = onCheckedChange)
        Text(label)
    }
}
