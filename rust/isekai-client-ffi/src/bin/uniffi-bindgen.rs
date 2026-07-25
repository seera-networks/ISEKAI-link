//! Standalone `uniffi-bindgen` so CI can generate the Swift bindings from the
//! built library:
//!
//! ```sh
//! cargo run -p isekai-client-ffi --bin uniffi-bindgen -- \
//!   generate --library <path-to-libisekai_client_ffi> --language swift --out-dir <dir>
//! ```
fn main() {
    uniffi::uniffi_bindgen_main()
}
