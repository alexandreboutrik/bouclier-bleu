use libbpf_cargo::SkeletonBuilder;

use std::env;
use std::path::PathBuf;

fn main() {
    let mut out =
        PathBuf::from(env::var_os("OUT_DIR")
            .expect("OUT_DIR must be set in build script"));

    out.push("lsm_enforcer.skel.rs");

    // This compiles the C code into eBPF bytecode and generates a Rust skeleton
    SkeletonBuilder::new()
        .source("../bpf/lsm_enforcer.bpf.c")
        .clang_args(["-I../bpf/include"])
        .build_and_generate(&out)
        .expect("Failed to compile eBPF code");
        
    println!("cargo:rerun-if-changed=../bpf/lsm_enforcer.bpf.c");
}
