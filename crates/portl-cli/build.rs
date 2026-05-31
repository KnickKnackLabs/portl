use std::path::PathBuf;

fn main() {
    let plist = PathBuf::from(std::env::var_os("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR"))
        .join("resources/macos/PortlInfo.plist");
    println!("cargo:rerun-if-changed={}", plist.display());

    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("macos") {
        println!(
            "cargo:rustc-link-arg-bin=portl=-Wl,-sectcreate,__TEXT,__info_plist,{}",
            plist.display()
        );
    }
}
