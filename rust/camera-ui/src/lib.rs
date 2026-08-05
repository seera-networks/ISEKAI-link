//! Screens both desktop apps show.

use camera_core::privacy::{self, Language};

/// The privacy policy, shown until it is agreed to.
///
/// Using ISEKAI link needs an account and that means personal information, so
/// nothing else in the application is reachable until this is answered. It is
/// drawn over whatever the application would have drawn rather than beside it —
/// a consent screen that can be scrolled past is not a consent screen.
///
/// Agreement is to a *version*: after the policy is revised this comes back on
/// the next start, once, and records the new answer. See
/// [`camera_core::privacy`].
pub struct ConsentGate {
    /// Names the record, so the two apps on one machine are answered
    /// separately — they are separate installations to the person using them.
    app: &'static str,
    language: Language,
    /// `false` until this build's policy version has been agreed to.
    satisfied: bool,
    /// Set when the answer could not be written down. Agreeing again every
    /// start is worse than saying what went wrong, so this is shown rather than
    /// swallowed.
    error: Option<String>,
}

impl ConsentGate {
    /// Read what this user has already agreed to.
    pub fn new(app: &'static str) -> Self {
        let recorded = privacy::load(app);
        Self {
            app,
            language: Language::preferred(),
            satisfied: !privacy::needs_agreement(recorded.as_ref()),
            error: None,
        }
    }

    /// Draw the policy if it still needs answering.
    ///
    /// Returns whether the application may carry on. Call it first in the
    /// frame and return early when it says no.
    pub fn show(&mut self, ui: &mut egui::Ui) -> bool {
        if self.satisfied {
            return true;
        }
        ui.vertical(|ui| {
            ui.horizontal(|ui| {
                ui.heading("プライバシーポリシー / Privacy Policy");
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if ui.button(self.language.other_label()).clicked() {
                        self.language = self.language.toggled();
                    }
                });
            });
            ui.label(
                egui::RichText::new(
                    "ISEKAI link の利用にはアカウント登録が必要で、個人情報を取得します。\
                     続けるには以下に同意してください。 / Using ISEKAI link requires an \
                     account and collects personal information. Please agree to continue.",
                )
                .small(),
            );
            ui.hyperlink_to(privacy::URL, privacy::URL);
            ui.separator();

            // The buttons are laid out before the text so they keep their place
            // at the bottom whatever the text's length; the scroll area then
            // takes what is left. Otherwise a long policy pushes the thing the
            // person is looking for off the window.
            let buttons = 64.0;
            let height = (ui.available_height() - buttons).max(120.0);
            egui::ScrollArea::vertical()
                .max_height(height)
                .auto_shrink([false, false])
                .show(ui, |ui| {
                    ui.label(self.language.text());
                });

            ui.separator();
            if let Some(error) = &self.error {
                ui.colored_label(
                    egui::Color32::LIGHT_RED,
                    format!("同意を記録できませんでした / could not record consent: {error}"),
                );
            }
            ui.horizontal(|ui| {
                if ui
                    .button(egui::RichText::new("同意する / Agree").strong())
                    .clicked()
                {
                    match privacy::save(self.app, self.language) {
                        Ok(consent) => {
                            tracing::info!(
                                version = %consent.version,
                                at = %consent.accepted_at,
                                "privacy policy agreed",
                            );
                            self.satisfied = true;
                        }
                        // Agreed, but unrecorded. Letting them through would
                        // ask again on every start; saying so lets it be fixed.
                        Err(e) => self.error = Some(format!("{e:#}")),
                    }
                }
                if ui.button("同意しない（終了） / Decline (quit)").clicked() {
                    ui.ctx().send_viewport_cmd(egui::ViewportCommand::Close);
                }
            });
        });
        self.satisfied
    }
}
