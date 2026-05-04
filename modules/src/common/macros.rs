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

use crate::common::traits::SecurityModule;
use crate::{exec_block, mount_secure, rename_entropy, shield, strict_wx};
use std::sync::Arc;

/// Inversion of Control (IoC) Registry Builder.
///
/// Constructs the active defense matrix. The core engine remains agnostic to
/// specific threat heuristics, iterating purely over this dynamic trait object
/// matrix.
pub fn build_registry() -> Vec<Arc<dyn SecurityModule + Send + Sync>> {
	vec![
		Arc::new(exec_block::ExecBlock::new()),
		Arc::new(rename_entropy::RenameEntropy::new()),
		Arc::new(shield::Shield::new()),
		Arc::new(mount_secure::MountSecure::new()),
		Arc::new(strict_wx::StrictWx::new()),
		// Future expansions: e.g. Arc::new(ransomware_heur::CanaryDrop::new()),
	]
}

/// Declarative factory macro for generating `SecurityModule` boilerplate.
///
/// Enforces a strict "No Unsafe" boundary. Callers must inject a purely safe
/// parsing function (`$parser`) to validate raw kernel bytes before the
/// payload reaches the heuristic engine.
#[macro_export]
macro_rules! define_security_module {
    (
        struct: $struct_name:ident,
        name: $name:expr,
        slug: $slug:expr,
        parser: $parser:path,
        handler: $handler:expr
        $(, capacities: $capacities_closure:expr)?
        $(, init: $init_closure:expr)?
    ) => {
        pub struct $struct_name {
            is_active: std::sync::atomic::AtomicBool,
        }

        impl $struct_name {
            pub fn new() -> Self {
                Self {
                    is_active: std::sync::atomic::AtomicBool::new(true),
                }
            }
        }

        impl Default for $struct_name {
            fn default() -> Self {
                Self::new()
            }
        }

        impl $crate::common::traits::SecurityModule for $struct_name {
            fn name(&self) -> &'static str {
                $name
            }
            fn slug(&self) -> &'static str {
                $slug
            }

            fn status(&self) -> bool {
                /*
                 * Ordering::Relaxed is sufficient for the high-frequency read
                 * loop. We prioritize CPU cache-coherency performance over
                 * strict synchronization for a simple boolean flag.
                 */
                self.is_active.load(std::sync::atomic::Ordering::Relaxed)
            }

            fn toggle(&self, state: bool) {
                /*
                 * Ordering::SeqCst ensures the state change from the IPC
                 * thread is immediately visible to the RingBuffer polling
                 * thread.
                 */
                self.is_active
                    .store(state, std::sync::atomic::Ordering::SeqCst);
                println!(
                    "Bouclier Bleu [Control]: {} active state -> {}",
                    self.slug(),
                    state
                );
            }

            fn process_event(&self, event_data: &[u8]) {
                if !self.status() {
                    return;
                }

                /*
                 * Utilize the strictly safe, module-specific parsing logic.
                 * If the kernel payload is malformed or maliciously tampered
                 * with, it is caught here before entering the heuristic
                 * engine.
                 */
                match $parser(event_data) {
                    Ok(alert) => {
                        /*
                         * NDJSON Pipeline
                         * Automatically intercept the parsed, safe Rust struct
                         * and forward it to the standardized SIEM JSON log
                         * before executing localized remediation closures.
                         * This guarantees zero-code integration for all
                         * modules.
                         */
                        $crate::common::telemetry::emit_siem_event($slug, &alert);

                        // Pass the validated payload to the localized logic
                        // block
                        $handler(alert);
                    }
                    Err(e) => {
                        eprintln!(
                            "Bouclier Bleu [Error]: {} failed to parse kernel event: {}",
                            self.slug(),
                            e
                        );
                    }
                }
            }

            fn map_capacities(&self) -> std::collections::HashMap<String, u32> {
                let mut _caps = std::collections::HashMap::new();
                $(
                    _caps = $capacities_closure();
                )?
                _caps
            }

            /*
             * Declarative Lifecycle Execution
             * Encapsulates the module-specific setup closure defined during
             * macro invocation. It safely passes the map resolution context
             * down to the heuristic logic while maintaining the strict
             * safe-Rust boundary enforced by the IoC registry.
             */
            fn init(&self, _provider: &dyn $crate::common::traits::MapProvider) -> Result<(), String> {
                $(
                    $init_closure(_provider)?;
                )?
                Ok(())
            }
        }
    };
}
