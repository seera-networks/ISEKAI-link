//! Standalone `uniffi-bindgen` so the Android Gradle build can generate the
//! Kotlin bindings from the built library, same pattern as
//! isekai-client-ffi/src/bin/uniffi-bindgen.rs:
//!
//! ```sh
//! cargo run -p portal-client-ffi --bin uniffi-bindgen -- \
//!   generate --library <path-to-libportal_client_ffi> --language kotlin --out-dir <dir>
//! ```
fn main() {
    uniffi::uniffi_bindgen_main()
}
