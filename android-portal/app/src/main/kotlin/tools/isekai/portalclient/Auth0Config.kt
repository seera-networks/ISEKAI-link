package tools.isekai.portalclient

/**
 * Where the app logs in, and what it asks a token for.
 *
 * Copied from `cameraclient/Auth0Config.kt` -- `domain`/`clientId`/`audience`
 * are shared across every ISEKAI-link app (native OAuth client, no secret, so
 * this is an identifier not a credential).
 *
 * `CALLBACK_SCHEME` is also shared, deliberately, as of Kozuka's "unified
 * callback" decision (2026-08-24): every ISEKAI-link app redirects to the
 * same `isekaiviewer://callback`, rather than each app registering its own
 * entry in Auth0's Allowed Callback URLs list. This app used to have its own
 * `isekaiportal://callback` specifically to avoid Android's disambiguation
 * chooser when two apps claim the same scheme+host -- that tradeoff is now
 * accepted deliberately rather than avoided, in exchange for not needing a
 * dashboard change per app. If both this app and a camera app are installed
 * on the same phone, expect the OS to prompt which app should handle the
 * redirect the first time (or to need re-selecting if the phone's default
 * changes) -- reasonable to route around only if this happens in practice
 * (a click-to-continue or "on this device" default preference does it).
 *
 * **This is a UX question, not a security one, because the flow is
 * Authorization Code + PKCE** (`Auth0Client.kt`): the code this redirect
 * carries is worthless without the verifier, which never leaves this app's
 * memory. A second app that claims `isekaiviewer://callback` -- by the
 * chooser prompt above, or by intercepting before the user picks -- gets a
 * code it cannot redeem, not a stolen session. Worth keeping in mind before
 * "fixing" the chooser prompt by giving this app its own scheme back: that
 * would undo the dashboard-change tradeoff above for a problem PKCE already
 * closed.
 */
object Auth0Config {
    const val DOMAIN = "seera-networks.jp.auth0.com"
    const val CLIENT_ID = "FeDSXYhJsfV1d9v6JyBte874R6En4tok"
    const val AUDIENCE = "https://masque.seera-networks.com/"

    /** `offline_access` is what makes Auth0 return a refresh token. */
    const val SCOPE = "openid profile email offline_access"

    /**
     * The scheme half of the redirect URI. Must also match the
     * `<data android:scheme=...>` in AndroidManifest.xml's intent-filter for
     * `.MainActivity`. Shared with every other ISEKAI-link app -- see the
     * class doc comment above.
     */
    const val CALLBACK_SCHEME = "isekaiviewer"
    const val REDIRECT_URI = "$CALLBACK_SCHEME://callback"
}
