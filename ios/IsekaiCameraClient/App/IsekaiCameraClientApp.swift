import SwiftUI

@main
struct IsekaiCameraClientApp: App {
    /// Held by the app rather than a view, so agreeing settles it for the
    /// session however the view below is rebuilt.
    @StateObject private var consent = PrivacyConsentStore()

    var body: some Scene {
        WindowGroup {
            ContentView()
                // Over the top, and not dismissable: using the service means an
                // account and personal information, so this is what a new
                // install sees first and the only thing it can act on. It comes
                // back once after the policy is revised, because the version
                // that was agreed to no longer matches the one bundled.
                .fullScreenCover(isPresented: $consent.needsAgreement) {
                    PrivacyConsentView(store: consent)
                }
        }
    }
}
