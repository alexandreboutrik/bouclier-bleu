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

use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "bouclier", about = "Bouclier Bleu Control Plane", version)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Check the status of the EDR
    Status,
    /// Enable a specific defense module
    Enable { module: String },
}

fn main() {
    let cli = Cli::parse();

    match &cli.command {
        Commands::Status => {
            println!("🛡️ Bouclier Bleu EDR Status: KERNEL ENGINE RUNNING");
        }
        Commands::Enable { module } => {
            println!("· Enabling module: {}", module);
            println!("(Future: This will send a Unix Socket message to the `core` daemon)");
        }
    }
}
