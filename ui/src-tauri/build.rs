// ui/src-tauri/build.rs
// Standard Tauri build script + placeholder for future macOS Network Extension / XPC bridge support.
//
// When we add native bridging (e.g. swift-rs to call Swift activation/XPC helpers,
// or direct objc2 calls for OSSystemExtensionRequest from Rust), put the build-time
// linking / codegen here.

fn main() {
    tauri_build::build();

    // === Future: macOS NE / XPC bridge notes (see extension/integration.md) ===
    // - If using swift-rs: add println!("cargo:rerun-if-changed=..."); and link the generated bridge.
    // - If bundling a small Swift dylib for XPC listener: ensure it's copied as a framework/resource
    //   and rpath / install_name_tool handled here or in a post-build script.
    // - Cargo features can gate this: e.g. #[cfg(feature = "macos-ne-bridge")]
    //
    // Example skeleton (uncomment when ready):
    // #[cfg(target_os = "macos")]
    // {
    //     println!("cargo:rustc-link-lib=framework=SystemExtensions");
    //     // println!("cargo:rustc-link-lib=framework=NetworkExtension");
    // }
}
