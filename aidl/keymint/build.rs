use std::env;
use std::path::PathBuf;

use aidlgen::Source;
use glob::glob;

fn main() -> std::io::Result<()> {
    let mut workspace_dir = env::current_dir().unwrap();
    workspace_dir.pop();
    workspace_dir.pop();

    let includes = &[
        Source {
            dir: workspace_dir.join("aosp/hardware/interfaces/security/keymint/aidl"),
            package: "android.hardware.security.keymint".to_owned(),
            version: "3".to_owned(),
        },
        Source {
            dir: workspace_dir.join("aosp/hardware/interfaces/security/secureclock/aidl"),
            package: "android.hardware.security.secureclock".to_owned(),
            version: "1".to_owned(),
        },
    ];

    let output_dir = PathBuf::from(env::var("OUT_DIR").unwrap());

    aidlgen::Builder::new()
        .args([
            "--lang=rust",
            "--stability=vintf",
            "--structured",
            "--omit_invocation",
        ])
        .source(&includes[0])
        .output(&output_dir)
        .includes(includes)
        .generate()?;

    glob(&format!("{}/**/*.aidl", includes[0].dir.to_str().unwrap()))
        .unwrap()
        .map(|x| x.unwrap())
        .for_each(|x| println!("cargo::rerun-if-changed={}", x.to_str().unwrap()));
    println!("cargo::rustc-cfg=android_vndk");
    Ok(())
}
