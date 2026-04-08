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
use quote::{format_ident, quote};

use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

/// Translates snake_case C filenames into CamelCase Rust identifiers.
/// Required because libbpf-rs automatically generates skeleton builder
/// structs utilizing CamelCase conventions (e.g., `exec_block.bpf.c` is 
/// compiled into `ExecBlockSkelBuilder`).
fn snake_to_camel(s: &str) -> String {
    s.split('_').map(|w| {
        let mut c = w.chars();
        match c.next() {
            None => String::new(),
            Some(f) => f.to_uppercase().collect::<String>() + c.as_str(),
        }
    }).collect()
}

fn main() {
    let out_dir = PathBuf::from(env::var_os("OUT_DIR").
        expect("OUT_DIR must be set"));

    /*
     * Restrict build cache invalidation to the eBPF source directory.
     * This prevents expensive recompilations of the Rust workspace unless
     * the underlying C code or headers actually change.
     */
    println!("cargo:rerun-if-changed=../bpf");

    /*
     * Replicate the 'include/' directory structure within Cargo's isolated
     * OUT_DIR. The eBPF C code strictly includes "include/vmlinux.h". By
     * staging it here and passing -I<OUT_DIR> to Clang, we satisfy the
     * compiler's relative path resolution without mutating the tracked Git
     * repository.
     */
    let out_include_dir = out_dir.join("include");
    if !out_include_dir.exists() {
        fs::create_dir_all(&out_include_dir)
            .expect("Failed to create include directory in OUT_DIR");
    }

    let vmlinux_path = out_include_dir.join("vmlinux.h");

    let bpf_dir = Path::new("../bpf");
    let bpf_include_dir = bpf_dir.join("include");

    if !bpf_include_dir.exists() {
        fs::create_dir_all(&bpf_include_dir)
            .expect("Failed to construct ../bpf/include directory");
    }
    
    /*
     * Dynamically dump the BPF Type Format (BTF) from the currently running
     * kernel into a fresh vmlinux.h. This architectural choice ensures the
     * eBPF objects are compiled against the exact memory layouts of the host
     * system, enabling CO-RE (Compile Once - Run Everywhere) without
     * committing a 100k+ line header.
     */
    let bpftool_out = Command::new("bpftool")
        .args(["btf", "dump", "file", "/sys/kernel/btf/vmlinux", "format", "c"])
        .output()
        .expect("Failed to execute bpftool. Is linux-tools-common installed?");

    if !bpftool_out.status.success() {
        panic!(
            "Failed to dump vmlinux.h. bpftool stderr: {}", 
            String::from_utf8_lossy(&bpftool_out.stderr)
        );
    }

    fs::write(&vmlinux_path, bpftool_out.stdout)
        .expect("Failed to write dynamically generated vmlinux.h");

    let entries = fs::read_dir(bpf_dir).expect("Failed to read bpf dir");
    
    let mut module_includes = Vec::new();
    let mut load_arms       = Vec::new();
    let mut toggle_arms     = Vec::new();
    let mut get_map_arms    = Vec::new();
    let mut module_names    = Vec::new();

    let clang_include_bpf = format!("-I{}", bpf_include_dir.display());
    let clang_include_out = format!("-I{}", out_dir.display());

    for entry in entries {
        let entry = entry.unwrap();
        let path = entry.path();

        if path.is_file() && path.extension().unwrap_or_default() == "c" {
            let file_name = path.file_name().unwrap().to_str().unwrap();
            
            if file_name.ends_with(".bpf.c") {
                let base_name = file_name.trim_end_matches(".bpf.c");
                let skel_name = format!("{}.skel.rs", base_name);
                let out_path = out_dir.join(&skel_name);

                /*
                 * Orchestrate the eBPF compilation pipeline:
                 * 1. Invokes Clang to compile the C source into a BPF ELF
                 * object.
                 * 2. Invokes bpftool to generate strongly-typed Rust bindings
                 * (skeletons) that safely wrap the BPF maps and programs.
                 */
                SkeletonBuilder::new()
                    .source(&path)
                    .clang_args([
                        clang_include_bpf.as_str(),
                        clang_include_out.as_str(),
                    ])
                    .build_and_generate(&out_path)
                    .unwrap_or_else(|e| panic!("Failed to compile {}: {:?}",
                            file_name, e));

                /*
                 * Leverage AST generation (via the `quote` crate) rather than
                 * raw string concatenation to build the loader module. This
                 * guarantees that the injected Rust code is syntactically
                 * sound and resilient to complex macro expansions at compile
                 * time.
                 */
                let mod_ident = format_ident!("{}", base_name);
                let builder_ident = format_ident!("{}SkelBuilder", snake_to_camel(base_name));
                let skel_ident = format_ident!("{}Skel", snake_to_camel(base_name));

                module_includes.push(quote! {
                    #[allow(non_camel_case_types, non_snake_case, dead_code)]
                    pub mod #mod_ident {
                        include!(concat!(env!("OUT_DIR"), "/", #skel_name));
                    }
                });

                module_names.push(base_name.to_string());
                    
                /*
                 * Generate the state machine transitions for dynamically
                 * attaching the BPF hooks into the kernel during daemon
                 * initialization.
                 */
                load_arms.push(quote! {
                    stringify!(#mod_ident) => {
                        let builder = #mod_ident::#builder_ident::default();
                        let open_skel = builder.open().context(concat!("Failed to open ", stringify!(#mod_ident)))?;
                        let mut skel = open_skel.load().context(concat!("Failed to load ", stringify!(#mod_ident)))?;
                        skel.attach().context(concat!("Failed to attach ", stringify!(#mod_ident)))?;
                        Ok(Box::new(skel))
                    }
                });

                /*
                 * DYNAMIC MAP RESOLUTION
                 * Instead of guessing if `state_map` exists by parsing C code, 
                 * we generate logic that dynamically attempts to look up the
                 * map by name within the libbpf object at runtime. If it
                 * doesn't exist (e.g., telemetry-only modules), it gracefully
                 * bypasses the update.
                 */
                let map_update_logic = quote! {
                    if let Some(state_map) = skel.obj.map("state_map") {
                        let key: [u8; 4] = 0u32.to_ne_bytes();
                        let val: [u8; 4] = if active { 1u32 } else { 0u32 }.to_ne_bytes();
                        
                        state_map.update(&key[..], &val[..], MapFlags::ANY)
                            .context(concat!("Failed to synchronize eBPF state_map for ", stringify!(#mod_ident)))?;
                    }
                };

                // Generate dynamic dispatch arms for map state synchronization
                toggle_arms.push(quote! {
                    stringify!(#mod_ident) => {
                        // Safely downcast the generic Any trait object
                        if let Some(skel) = skel.downcast_ref::<#mod_ident::#skel_ident>() {
                            #map_update_logic
                            Ok(())
                        } else {
                            bail!("Type downcast failed for module skeleton '{}'", name);
                        }
                    }
                });

                /*
                 * DYNAMIC MAP EXTRACTION
                 * Generates a safe downcast attempt for this specific module
                 * skeleton. If the downcast succeeds, it utilizes the
                 * underlying libbpf `Object` to dynamically resolve the
                 * requested map by its string name.
                 */
                get_map_arms.push(quote! {
                    if let Some(downcasted_skel) = skel.downcast_ref::<#mod_ident::#skel_ident>() {
                        if let Some(map) = downcasted_skel.obj.map(map_name) {
                            return Ok(map);
                        } else {
                            bail!("Map '{}' not found in module skeleton", map_name);
                        }
                    }
                });
            }
        }
    }

    let names = module_names.iter().map(|n| quote! { #n });

    // Construct a unified loader interface (`bpf_loader.rs`).
    let final_code = quote! {
        use anyhow::{Context, Result, bail};
        use std::any::Any;
        use libbpf_rs::skel::{OpenSkel, Skel, SkelBuilder};
        use libbpf_rs::MapFlags;

        #(#module_includes)*

        pub fn available_modules() -> Vec<&'static str> {
            vec![ #(#names),* ]
        }

        /// Dispatches module loading logic dynamically based on string names.
        pub fn load_module(name: &str) -> Result<Box<dyn Any>> {
            match name {
                #(#load_arms)*
                _ => bail!("eBPF module '{}' not found.", name),
            }
        }

        /// Synchronizes the administrative state with the kernel-space BPF map.
        /// Prevents Denial-of-Service and pipeline breakage by toggling logic 
        /// in the kernel context instead of dropping the full LSM link
        /// descriptor.
        pub fn set_module_state(skel: &dyn Any, name: &str, active: bool) -> Result<()> {
            match name {
                #(#toggle_arms)*
                _ => bail!("Unknown eBPF module '{}'", name),
            }
        }

        /// Dynamically retrieves a reference to a BPF Map by its string
        /// identifier. Iterates through available skeleton types to
        /// successfully downcast the `Any` trait object, eliminating the need
        /// to hardcode map accessors in userland.
        pub fn get_map<'a>(skel: &'a dyn Any, map_name: &str) -> Result<&'a libbpf_rs::Map> {
            #(#get_map_arms)*
            bail!("Type downcast failed or map '{}' not found across all registered modules.", map_name)
        }
    };

    fs::write(out_dir.join("bpf_loader.rs"), final_code.to_string())
        .expect("Failed to write bpf_loader.rs");
}
