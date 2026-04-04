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

use std::sync::Arc;

pub mod exec_block;

/*
 * SECURITY MODULE CONTRACT
 * This trait establishes the architectural boundary between the generalized 
 * eBPF event router (Core) and specialized defensive heuristics (Modules).
 * Concurrency Requirements (`Send + Sync`):
 * Modules are instantiated once at boot and shared across multiple threads 
 * (the Main Actor loop and the IPC loop) via `Arc`. Therefore, all
 * implementors must guarantee thread-safe interior mutability (e.g., using
 * atomics or mutexes).
 */
pub trait SecurityModule: Send + Sync {
    /// The human-readable operational name for UI/CLI presentation.
    fn name(&self) -> &'static str;

    /// The unique system identifier used by the IPC router for targeting.
    fn slug(&self) -> &'static str;

    /// Returns the real-time operational state. 
    /// `false` indicates the module should silently drop routed kernel events.
    fn status(&self) -> bool;

    /// Instructs the module to alter its active state.
    fn toggle(&self, state: bool);

    /*
     * High-Performance Event Processing:
     * Receives raw byte slices directly from the kernel BPF RingBuffer.
     * Implementations must handle zero-copy deserialization locally to 
     * prevent bottlenecking the core router thread.
     */
    fn process_event(&self, event_data: &[u8]);
}

/*
 * INVERSION OF CONTROL (IoC) REGISTRY
 * By constructing the registry inside the `modules` crate, the `core` engine 
 * remains entirely agnostic to specific defense implementations. It only
 * knows how to iterate over `Arc<dyn SecurityModule>`.
 */
pub fn build_registry() -> Vec<Arc<dyn SecurityModule + Send + Sync>> {
    vec![
        Arc::new(exec_block::ExecBlock::new()),
        // Future expansion: Arc::new(ransomware_heur::CanaryDrop::new()),
    ]
}
