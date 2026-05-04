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

use serde::Deserialize;
use std::collections::HashMap;
use std::fs::File;
use std::io::Read;
use std::os::unix::fs::MetadataExt;
use std::path::Path;

/// Strongly typed representation of the daemon's TOML configuration.
#[derive(Deserialize, Debug, Default)]
pub struct DaemonConfig {
	/// A map of module slugs to their default startup state (true = enabled, false =
	/// disabled).
	#[serde(default)]
	pub modules: HashMap<String, bool>,
}

impl DaemonConfig {
	/// Discovers, parses, and loads the configuration file.
	/// Falls back to default values if no file is found to prevent daemon crashes.
	pub fn load() -> Self {
		// Enforce strict production pathing in release builds.
		#[cfg(not(debug_assertions))]
		let search_paths = ["/etc/bouclier-bleu/config.toml"];

		// Allow local working-directory fallbacks during development.
		#[cfg(debug_assertions)]
		let search_paths = ["/etc/bouclier-bleu/config.toml", "config.toml"];

		for path in search_paths {
			if Path::new(path).exists() {
				/*
				 * Descriptor-Oriented File Operations
				 * We open the file first, then request metadata on the active
				 * descriptor. This completely neutralizes TOCTOU symlink/swap
				 * attacks between the permission check and the actual read
				 * operation.
				 */
				let Ok(mut file) = File::open(path) else {
					continue;
				};

				let Ok(metadata) = file.metadata() else {
					continue;
				};

				if metadata.uid() != 0 {
					panic!(
						"FATAL: Configuration file {} is not owned by root! Aborting to prevent privilege escalation.",
						path
					);
				}

				let mut contents = String::new();
				match file.read_to_string(&mut contents) {
					Ok(_) => match toml::from_str(&contents) {
						Ok(config) => {
							println!("· [Config] Loaded configuration from {}", path);
							return config;
						}
						Err(e) => {
							eprintln!(
                                "· [Error] Failed to parse TOML in {}: {}. Falling back to default configuration to avoid fail-open state.",
                                path, e
                            );
							return Self::default();
						}
					},
					Err(e) => eprintln!("· [Warning] Failed to read {}: {}", path, e),
				}
			}
		}

		println!("· [Config] No configuration file found. Operating with implicit defaults.");
		Self::default()
	}
}
