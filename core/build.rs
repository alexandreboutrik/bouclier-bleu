// SPDX-License-Identifier: Apache-2.0
//
// Copyright 2026 The Bouclier Bleu Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

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
