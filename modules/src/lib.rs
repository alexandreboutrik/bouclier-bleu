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

//! Core Abstractions for Bouclier Bleu Security Modules.
//!
//! This module provides the `SecurityModule` contract and the IoC registry, 
//! decoupling specific defensive heuristics from the core eBPF routing engine.

use std::sync::Arc;

pub mod exec_block;

/// Defines the architectural boundary between the generalized eBPF event
/// router and specialized defensive heuristics.
///
/// Modules are instantiated once at boot and shared across asynchronous worker 
/// threads (the Main Actor loop and the IPC loop) via `Arc`. Implementors 
/// must guarantee thread-safe interior mutability.
pub trait SecurityModule: Send + Sync {
    /// The human-readable operational name for UI/CLI presentation.
    fn name(&self) -> &'static str;

    /// The unique system identifier used by the IPC router for mapping incoming 
    /// daemon commands to the correct instance.
    fn slug(&self) -> &'static str;

    /// Returns the real-time operational state. 
    /// `false` indicates the module should silently drop routed kernel events.
    fn status(&self) -> bool;

    /// Instructs the module to alter its active state.
    fn toggle(&self, state: bool);

    /// Ingestion pipeline for kernel telemetry.
    ///
    /// Receives raw byte slices directly from the BPF RingBuffer.
    /// Implementations are strictly responsible for safe deserialization to
    /// uphold memory safety across the kernel/user boundary.
    fn process_event(&self, event_data: &[u8]);
}

/// Inversion of Control (IoC) Registry Builder.
///
/// Constructs the active defense matrix. The core engine remains agnostic to 
/// specific threat heuristics, iterating purely over this dynamic trait object
/// matrix.
pub fn build_registry() -> Vec<Arc<dyn SecurityModule + Send + Sync>> {
    vec![
        Arc::new(exec_block::ExecBlock::new()),
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
            fn default() -> Self { Self::new() }
        }

        impl crate::SecurityModule for $struct_name {
            fn name(&self) -> &'static str { $name }
            fn slug(&self) -> &'static str { $slug }

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
                 * thread  is immediately visible to the RingBuffer polling
                 * thread.
                 */
                self.is_active.store(state, std::sync::atomic::Ordering::SeqCst);
                println!("Bouclier Bleu [Control]: {} active state -> {}", self.slug(), state);
            }
            
            fn process_event(&self, event_data: &[u8]) {
                if !self.status() { return; }

                /*
                 * Utilize the strictly safe, module-specific parsing logic.
                 * If the kernel payload is malformed or maliciously tampered
                 * with, it is caught here before entering the heuristic
                 * engine.
                 */
                match $parser(event_data) {
                    Ok(alert) => {
                        // Pass the validated, purely safe Rust struct to the
                        // logic block
                        $handler(alert);
                    }
                    Err(e) => {
                        eprintln!("Bouclier Bleu [Error]: {} failed to parse kernel event: {}", self.slug(), e);
                    }
                }
            }
        }
    };
}
