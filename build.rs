use std::path::{Path, PathBuf};
use std::process::Command;

const BPF_SRC: &str = "bpf/firewall.bpf.c";
const VENDOR: &str = "bpf/vendor";

fn find_in_path(env: &str, default: &str, candidates: &[&str]) -> String {
    if let Ok(v) = std::env::var(env) {
        if !v.is_empty() {
            return v;
        }
    }
    for cand in candidates {
        let path = Path::new(cand);
        if path.exists() {
            return cand.to_string();
        }
    }
    let _ = default;
    default.to_string()
}

fn main() {
    println!("cargo:rerun-if-changed={BPF_SRC}");
    println!("cargo:rerun-if-changed={VENDOR}");

    let clang = find_in_path(
        "CLANG",
        "clang",
        &["/usr/bin/clang", "/usr/local/bin/clang", "/opt/homebrew/bin/clang"],
    );
    let llvm_strip = find_in_path(
        "LLVM_STRIP",
        "llvm-strip",
        &[
            "/usr/lib/llvm-21/bin/llvm-strip",
            "/usr/lib/llvm-20/bin/llvm-strip",
            "/usr/lib/llvm-19/bin/llvm-strip",
            "/usr/lib/llvm-18/bin/llvm-strip",
            "/usr/bin/llvm-strip",
            "/usr/local/bin/llvm-strip",
        ],
    );

    let out_dir = PathBuf::from(std::env::var("OUT_DIR").expect("OUT_DIR"));
    let obj = out_dir.join("firewall.bpf.o");

    let mut cmd = Command::new(&clang);
    cmd.args(["-O2", "-target", "bpf", "-g", "-Wall", "-Werror"]);
    cmd.arg("-I").arg(VENDOR);
    cmd.arg("-c").arg(BPF_SRC);
    cmd.arg("-o").arg(&obj);
    let status = cmd
        .status()
        .expect("failed to spawn clang; install clang/llvm to build the eBPF program");
    assert!(
        status.success(),
        "clang failed to compile the eBPF program ({BPF_SRC})"
    );

    // Strip DWARF debug info but keep .BTF/.BTF.ext, which aya requires to
    // discover the map layouts and program types.
    let strip_status = Command::new(&llvm_strip).arg("-g").arg(&obj).status();
    match strip_status {
        Ok(status) if status.success() => {}
        _ => eprintln!("warning: llvm-strip unavailable, keeping DWARF in bpf.o"),
    }

    println!("cargo:rustc-env=ZQFW_BPF_OBJ={}", obj.display());
}
