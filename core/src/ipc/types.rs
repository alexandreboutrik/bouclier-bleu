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

use std::sync::mpsc;

/// Strongly typed RPC commands strictly parsed from raw socket payloads.
///
/// This enum acts as the serialization boundary, ensuring only syntactically
/// valid directives propagate to the core execution engine.
pub enum DaemonCmd {
	Status,
	List,
	Enable(String),
	Disable(String),
}

/// Represents an encapsulated transaction across the IPC boundary.
///
/// Includes a single-use transmission channel (`mpsc::Sender`) allowing the
/// asynchronous core engine to route execution results back to the synchronous
/// socket thread.
pub struct IpcMessage {
	pub cmd: DaemonCmd,
	pub reply: mpsc::Sender<String>,
}
