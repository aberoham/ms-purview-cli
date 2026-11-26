//! Records the target triple for `purview version`. Cargo gives `TARGET`
//! only to build scripts.

fn main() {
    let target = std::env::var("TARGET").unwrap_or_else(|_| "unknown".to_owned());
    println!("cargo:rustc-env=PURVIEW_BUILD_TARGET={target}");
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-env-changed=PURVIEW_BUILD_COMMIT");
}
