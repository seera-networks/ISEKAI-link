package tools.isekai.portalclient

import android.content.Context
import androidx.activity.compose.BackHandler
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.selection.SelectionContainer
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import java.time.Instant
import java.util.Locale
import uniffi.portal_client_ffi.PrivacyPolicy
import uniffi.portal_client_ffi.privacyPolicy

private const val PREFS_NAME = "privacy_consent"
private const val KEY_VERSION = "version"
private const val KEY_ACCEPTED_AT = "acceptedAt"
private const val KEY_LANGUAGE = "language"

/**
 * Whether this install has agreed to the privacy policy, and to which
 * version. A copy of the camera app's own `PrivacyConsentStore` (and so of
 * the iOS app's), kept the same on purpose: same preferences file, same keys,
 * same rule for asking again.
 *
 * Using ISEKAI link needs an account and that means personal information, so
 * the app asks before it does anything else and remembers the answer.
 *
 * **Agreement is to a version.** The text comes from the Rust core -- the
 * same one the camera apps and the CLIs show -- and carries a version with it.
 * Storing that version alongside the answer is what makes a revised policy
 * ask again instead of relying on a boolean that can never be undone.
 */
class PrivacyConsentStore(context: Context) {
    val policy: PrivacyPolicy = privacyPolicy()

    private val prefs = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)

    var needsAgreement: Boolean by mutableStateOf(prefs.getString(KEY_VERSION, null) != policy.version)
        private set

    fun agree(language: String) {
        prefs.edit()
            .putString(KEY_VERSION, policy.version)
            .putString(KEY_ACCEPTED_AT, Instant.now().toString())
            .putString(KEY_LANGUAGE, language)
            .apply()
        needsAgreement = false
    }
}

/**
 * The policy, shown until it is agreed to.
 *
 * Presented so that nothing behind it can be reached or dismissed past -- a
 * consent screen with a way around it is not a consent screen. There is no
 * "later": the only alternative offered is to stop, because without
 * agreement there is nothing the app can do.
 */
@Composable
fun PrivacyConsentScreen(store: PrivacyConsentStore) {
    // Blocks the system back gesture/button while this is on screen -- the
    // same "no way around it" rule as everything else here.
    BackHandler(enabled = true) {}

    var showJapanese by remember {
        mutableStateOf(Locale.getDefault().language == "ja")
    }
    val text = if (showJapanese) store.policy.textJa else store.policy.textEn
    val link = if (showJapanese) store.policy.urlJa else store.policy.urlEn

    Surface(modifier = Modifier.fillMaxSize()) {
        Column(
            modifier =
                Modifier
                    .fillMaxSize()
                    .padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically,
            ) {
                Text(
                    "プライバシーポリシー / Privacy Policy",
                    style = MaterialTheme.typography.titleMedium,
                )
                TextButton(onClick = { showJapanese = !showJapanese }) {
                    Text(if (showJapanese) "English" else "日本語")
                }
            }

            Text(
                "ISEKAI link の利用にはアカウント登録が必要で、個人情報を取得します。" +
                    "続けるには以下に同意してください。 / Using ISEKAI link requires an " +
                    "account and collects personal information. Please agree to continue.",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )

            Text(
                link,
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.primary,
            )

            HorizontalDivider()

            SelectionContainer(
                modifier =
                    Modifier
                        .weight(1f)
                        .verticalScroll(rememberScrollState()),
            ) {
                Text(
                    text,
                    fontFamily = FontFamily.Monospace,
                    style = MaterialTheme.typography.bodySmall,
                )
            }

            HorizontalDivider()

            Button(
                onClick = { store.agree(language = if (showJapanese) "ja" else "en") },
                modifier = Modifier.fillMaxWidth(),
            ) {
                Text("同意する / Agree")
            }

            Text(
                "同意いただけない場合、本アプリはご利用いただけません。 / " +
                    "The app cannot be used without agreement.",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                modifier = Modifier.fillMaxWidth(),
                textAlign = TextAlign.Center,
            )
        }
    }
}
