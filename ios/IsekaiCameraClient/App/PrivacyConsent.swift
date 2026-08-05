import SwiftUI

/// Whether this install has agreed to the privacy policy, and to which version.
///
/// Using ISEKAI link needs an account and that means personal information, so
/// the app asks before it does anything else and remembers the answer.
///
/// **Agreement is to a version.** The text comes from the Rust core — the same
/// one the desktop apps show — and carries a version with it. Storing that
/// version alongside the answer is what makes a revised policy ask again
/// instead of relying on a boolean that can never be undone.
@MainActor
final class PrivacyConsentStore: ObservableObject {
    private static let versionKey = "privacy.consent.version"
    private static let acceptedAtKey = "privacy.consent.acceptedAt"
    private static let languageKey = "privacy.consent.language"

    let policy: PrivacyPolicy
    @Published private(set) var needsAgreement: Bool

    init(policy: PrivacyPolicy = privacyPolicy()) {
        self.policy = policy
        let agreed = UserDefaults.standard.string(forKey: Self.versionKey)
        needsAgreement = agreed != policy.version
    }

    func agree(language: String) {
        let defaults = UserDefaults.standard
        defaults.set(policy.version, forKey: Self.versionKey)
        defaults.set(ISO8601DateFormatter().string(from: Date()), forKey: Self.acceptedAtKey)
        defaults.set(language, forKey: Self.languageKey)
        needsAgreement = false
    }
}

/// The policy, shown until it is agreed to.
///
/// Presented so that nothing behind it can be reached or dismissed past — a
/// consent screen with a way around it is not a consent screen. There is no
/// "later": the only alternative offered is to stop, because without agreement
/// there is nothing the app can do.
struct PrivacyConsentView: View {
    @ObservedObject var store: PrivacyConsentStore
    /// Japanese when the device asks for it, English otherwise. Agreeing to a
    /// document you cannot read is not agreement.
    @State private var showJapanese = Locale.preferredLanguages.first?.hasPrefix("ja") ?? false

    private var text: String {
        showJapanese ? store.policy.textJa : store.policy.textEn
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack {
                Text("プライバシーポリシー / Privacy Policy")
                    .font(.headline)
                Spacer()
                Button(showJapanese ? "English" : "日本語") {
                    showJapanese.toggle()
                }
            }

            Text(
                "ISEKAI link の利用にはアカウント登録が必要で、個人情報を取得します。"
                    + "続けるには以下に同意してください。 / Using ISEKAI link requires an "
                    + "account and collects personal information. Please agree to continue."
            )
            .font(.caption)
            .foregroundStyle(.secondary)

            if let url = URL(string: store.policy.url) {
                Link(store.policy.url, destination: url).font(.caption)
            }

            Divider()

            ScrollView {
                Text(text)
                    .font(.system(.footnote, design: .monospaced))
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .textSelection(.enabled)
            }

            Divider()

            Button {
                store.agree(language: showJapanese ? "ja" : "en")
            } label: {
                Text("同意する / Agree").bold().frame(maxWidth: .infinity)
            }
            .buttonStyle(.borderedProminent)

            Text("同意いただけない場合、本アプリはご利用いただけません。 / "
                 + "The app cannot be used without agreement.")
                .font(.caption2)
                .foregroundStyle(.secondary)
                .frame(maxWidth: .infinity, alignment: .center)
        }
        .padding()
        .interactiveDismissDisabled()
    }
}
