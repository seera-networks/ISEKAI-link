//! Making Japanese render at all.
//!
//! egui ships Latin faces and nothing else, so every Japanese character in the
//! interface draws as a blank box. That matters most exactly where this was
//! introduced: a privacy policy nobody can read is not a policy anybody has
//! agreed to.
//!
//! A face is borrowed from the operating system rather than bundled. Windows
//! and macOS always have one, and most desktop Linux installs do; bundling a
//! CJK face instead would add several megabytes to the repository and to every
//! build, which is a decision worth making deliberately rather than as a side
//! effect of fixing blank boxes. When nothing is found, [`install_japanese`]
//! says so and the caller shows the English text — see
//! [`crate::ConsentGate`], which stops offering a language it cannot draw.

use std::path::{Path, PathBuf};

/// Faces to look for, best first.
///
/// Names rather than a font-config query, because the platforms disagree about
/// everything except where they keep their fonts. Each entry is a full path on
/// one platform and absent on the others, so the list is simply tried in order.
#[cfg(target_os = "windows")]
const CANDIDATES: &[&str] = &[
    // Meiryo and Yu Gothic ship with every supported Windows; MS Gothic is the
    // fallback that has been there since long before them.
    r"C:\Windows\Fonts\meiryo.ttc",
    r"C:\Windows\Fonts\YuGothM.ttc",
    r"C:\Windows\Fonts\YuGothR.ttc",
    r"C:\Windows\Fonts\msgothic.ttc",
];

#[cfg(target_os = "macos")]
const CANDIDATES: &[&str] = &[
    "/System/Library/Fonts/ヒラギノ角ゴシック W3.ttc",
    "/System/Library/Fonts/ヒラギノ角ゴ ProN W3.ttc",
    "/Library/Fonts/ヒラギノ角ゴ ProN W3.otf",
    "/System/Library/Fonts/Hiragino Sans GB.ttc",
    // Not Japanese-specific, but it covers the range and is always present.
    "/Library/Fonts/Arial Unicode.ttf",
];

#[cfg(not(any(target_os = "windows", target_os = "macos")))]
const CANDIDATES: &[&str] = &[
    "/usr/share/fonts/opentype/noto/NotoSansCJK-Regular.ttc",
    "/usr/share/fonts/opentype/noto/NotoSansCJKjp-Regular.otf",
    "/usr/share/fonts/truetype/fonts-japanese-gothic.ttf",
    "/usr/share/fonts/truetype/vlgothic/VL-Gothic-Regular.ttf",
    "/usr/share/fonts/truetype/ipafont-gothic/ipag.ttf",
];

/// Directories to sweep when none of [`CANDIDATES`] is present.
///
/// Distributions move Noto around often enough that a fixed list misses it, and
/// a font that is installed but unfound looks identical to one that is not.
#[cfg(not(any(target_os = "windows", target_os = "macos")))]
const SEARCH_ROOTS: &[&str] = &["/usr/share/fonts", "/usr/local/share/fonts"];

#[cfg(any(target_os = "windows", target_os = "macos"))]
const SEARCH_ROOTS: &[&str] = &[];

/// Give `ctx` a Japanese face, if the machine has one.
///
/// Returns whether Japanese can now be drawn. Call once, before the first
/// frame; the face is added *behind* egui's own, so Latin text keeps the
/// shapes it had and only the characters egui cannot draw come from here.
pub fn install_japanese(ctx: &egui::Context) -> bool {
    let Some((path, bytes)) = find_font() else {
        tracing::warn!(
            "no Japanese font found on this system; Japanese text will be shown in \
             English instead. Install a CJK font (Noto Sans CJK, for example) to read it.",
        );
        return false;
    };

    let mut fonts = egui::FontDefinitions::default();
    const NAME: &str = "system-japanese";
    fonts.font_data.insert(
        NAME.to_owned(),
        // Index 0: the `.ttc` collections above lead with the regular weight,
        // which is the one wanted.
        std::sync::Arc::new(egui::FontData::from_owned(bytes).tweak(egui::FontTweak::default())),
    );
    // Appended rather than inserted at the front, for both families: egui's own
    // faces stay responsible for Latin, and this only supplies what they lack.
    for family in [egui::FontFamily::Proportional, egui::FontFamily::Monospace] {
        fonts
            .families
            .entry(family)
            .or_default()
            .push(NAME.to_owned());
    }
    ctx.set_fonts(fonts);
    tracing::info!(font = %path.display(), "Japanese font installed");
    true
}

/// The first readable candidate, with its bytes.
fn find_font() -> Option<(PathBuf, Vec<u8>)> {
    for candidate in CANDIDATES {
        let path = Path::new(candidate);
        if let Ok(bytes) = std::fs::read(path) {
            return Some((path.to_path_buf(), bytes));
        }
    }
    for root in SEARCH_ROOTS {
        if let Some(found) = search(Path::new(root), 0) {
            if let Ok(bytes) = std::fs::read(&found) {
                return Some((found, bytes));
            }
        }
    }
    None
}

/// Look for a CJK-looking face under `dir`.
///
/// Depth-limited: font trees are shallow, and an unbounded walk of a directory
/// somebody has symlinked is not worth the risk of a slow start.
fn search(dir: &Path, depth: usize) -> Option<PathBuf> {
    if depth > 3 {
        return None;
    }
    let entries = std::fs::read_dir(dir).ok()?;
    let mut subdirs = Vec::new();
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            subdirs.push(path);
            continue;
        }
        if is_japanese_font(&path) {
            return Some(path);
        }
    }
    subdirs.into_iter().find_map(|dir| search(&dir, depth + 1))
}

/// Whether a file name looks like a Japanese-capable face.
///
/// By name, because opening every font on the machine to read its character map
/// would cost more than it saves. A wrong guess costs blank boxes, which is
/// what is already happening without one.
fn is_japanese_font(path: &Path) -> bool {
    let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
        return false;
    };
    let name = name.to_ascii_lowercase();
    if !(name.ends_with(".ttf") || name.ends_with(".ttc") || name.ends_with(".otf")) {
        return false;
    }
    // "cjk" catches Noto's naming; the rest are the faces distributions ship
    // when they ship a Japanese one at all.
    [
        "cjk", "japanese", "gothic", "mincho", "vlgothic", "ipag", "ipam",
    ]
    .iter()
    .any(|needle| name.contains(needle))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The list is what makes this work on the platform being built for, so an
    /// empty one is a silent failure to render anything.
    #[test]
    fn there_are_candidates_for_this_platform() {
        assert!(!CANDIDATES.is_empty());
        assert!(CANDIDATES.iter().all(|c| !c.is_empty()));
    }

    #[test]
    fn font_files_are_recognised_by_name() {
        assert!(is_japanese_font(Path::new(
            "/usr/share/fonts/opentype/noto/NotoSansCJK-Regular.ttc"
        )));
        assert!(is_japanese_font(Path::new("/x/VL-Gothic-Regular.ttf")));
        assert!(is_japanese_font(Path::new(
            r"C:\Windows\Fonts\msgothic.ttc"
        )));
    }

    /// Latin faces are the ones egui already has; picking one up here would
    /// change the interface's shapes and still draw blank boxes.
    #[test]
    fn latin_faces_and_other_files_are_left_alone() {
        assert!(!is_japanese_font(Path::new("/x/DejaVuSans.ttf")));
        assert!(!is_japanese_font(Path::new("/x/Ubuntu-Light.ttf")));
        // The right name but not a font.
        assert!(!is_japanese_font(Path::new("/x/gothic.txt")));
        assert!(!is_japanese_font(Path::new("/x/NotoSansCJK-Regular.zip")));
    }

    /// A missing tree is the normal case on a machine with no fonts at all,
    /// and has to answer rather than fail.
    #[test]
    fn searching_somewhere_that_does_not_exist_finds_nothing() {
        assert!(search(Path::new("/nonexistent-font-root"), 0).is_none());
    }
}
