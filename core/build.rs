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

/// Normalizes module filenames into standard Rust struct identifiers.
/// Required to dynamically invoke libbpf-rs builder patterns (e.g.,
/// `exec_block` -> `ExecBlockSkelBuilder`).
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

    let bpf_dir = Path::new("../bpf");

    // Restrict build cache invalidation strictly to changes in the eBPF C
    // source directory.
    // Prevents unnecessary recompilation of the entire Rust workspace.
    println!("cargo:rerun-if-changed=../bpf");

    let entries = fs::read_dir(bpf_dir).expect("Failed to read bpf dir");
    
    let mut module_includes = Vec::new();
    let mut load_arms       = Vec::new();
    let mut module_names    = Vec::new();

    for entry in entries {
        let entry = entry.unwrap();
        let path = entry.path();

        if path.is_file() && path.extension().unwrap_or_default() == "c" {
            let file_name = path.file_name().unwrap().to_str().unwrap();
            
            if file_name.ends_with(".bpf.c") {
                let base_name = file_name.trim_end_matches(".bpf.c");
                let skel_name = format!("{}.skel.rs", base_name);
                let out_path = out_dir.join(&skel_name);

                // Compile the C source into eBPF object files and generate the 
                // strongly-typed Rust skeleton bindings.
                SkeletonBuilder::new()
                    .source(&path)
                    .clang_args(["-I../bpf/include"])
                    .build_and_generate(&out_path)
                    .unwrap_or_else(|e| panic!("Failed to compile {}: {}",
                            file_name, e));
                
                let mod_ident = format_ident!("{}", base_name);
                let builder_ident = format_ident!("{}SkelBuilder",
                    snake_to_camel(base_name));

                /*
                 * We use AST generation (via `quote`) rather than raw string
                 * concatenation. This ensures the injected Rust loader code is
                 * syntactically sound at build-time and safely handles complex
                 * macro expansions natively.
                 */
                module_includes.push(quote! {
                    #[allow(non_camel_case_types, non_snake_case, dead_code)]
                    pub mod #mod_ident {
                        include!(concat!(env!("OUT_DIR"), "/", #skel_name));
                    }
                });

                module_names.push(base_name.to_string());
                    
                // Generate the dynamic load match arm
                load_arms.push(quote! {
                    stringify!(#mod_ident) => {
                        let builder = #mod_ident::#builder_ident::default();
                        let open_skel = builder.open().context(concat!("Failed to open ", stringify!(#mod_ident)))?;
                        let mut skel = open_skel.load().context(concat!("Failed to load ", stringify!(#mod_ident)))?;
                        skel.attach().context(concat!("Failed to attach ", stringify!(#mod_ident)))?;
                        Ok(Box::new(skel))
                    }
                });
            }
        }
    }

    let names = module_names.iter().map(|n| quote! { #n });

    // Finalize the AST and write it to the build artifacts directory.
    // This file acts as a dynamic module loader that will be safely
    // `#include`d into the userland daemon's namespace.
    let final_code = quote! {
        use anyhow::{Context, Result, bail};
        use std::any::Any;
        use libbpf_rs::skel::{OpenSkel, Skel, SkelBuilder};

        #(#module_includes)*

        pub fn available_modules() -> Vec<&'static str> {
            vec![ #(#names),* ]
        }

        pub fn load_module(name: &str) -> Result<Box<dyn Any>> {
            match name {
                #(#load_arms)*
                _ => bail!("eBPF module '{}' not found.", name),
            }
        }
    };

    fs::write(out_dir.join("bpf_loader.rs"), final_code.to_string())
        .expect("Failed to write bpf_loader.rs");
}

