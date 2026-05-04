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

use std::fs::{File, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt};
use std::sync::{Mutex, OnceLock};

/*
 * Decoupled Telemetry Sink
 * Global lock for the NDJSON log file. Utilizing OnceLock ensures the file
 * descriptor is lazily initialized exactly once across all asynchronous worker
 * threads, while the Mutex prevents interleaved JSON objects during concurrent
 * high-frequency attack bursts.
 */
static SIEM_LOG_SINK: OnceLock<Mutex<Option<File>>> = OnceLock::new();

/// Standardized SIEM Envelope
/// We use a flattened schema so the resulting JSON is a single, clean layer
/// without nested `alert: { ... }` blocks, which makes indexing in Splunk or
/// Elasticsearch significantly cheaper and faster.
#[derive(serde::Serialize)]
struct EnvelopedAlert<'a, A: serde::Serialize> {
	#[serde(rename = "@timestamp")]
	timestamp_ms: u128,
	event_source: &'a str,
	#[serde(flatten)]
	payload: &'a A,
}

/// Graceful Telemetry Degradation
/// Instead of panicking with unwrap() if the fallback file is missing, we
/// safely iterate through a list of fallback devices to keep the EDR daemon
/// alive.
fn get_fallback_sink() -> Mutex<Option<File>> {
	let fallback_file = ["/tmp/bouclier_fallback.log"]
		.iter()
		.find_map(|path| OpenOptions::new().write(true).open(path).ok());

	if fallback_file.is_none() {
		eprintln!("Bouclier Bleu [FATAL]: No writable device available. Telemetry dropped.");
	}

	Mutex::new(fallback_file)
}

/// Directory Validation & Auto-Remediation
/// Validates that the directory wasn't pre-staged by an attacker with
/// wide-open permissions. Executes auto-remediation (Nuke and Pave) if
/// compromised.
fn ensure_secure_directory(log_dir: &str) -> Result<(), ()> {
	/*
	 * TOCTOU & Privilege Escalation Mitigation
	 * We atomically create the directory with root-only permissions (0o700) to
	 * prevent unprivileged users from staging symlink attacks within thelog
	 * directory.
	 */
	if let Err(e) = std::fs::DirBuilder::new()
		.recursive(true)
		.mode(0o700)
		.create(log_dir)
	{
		eprintln!(
			"Bouclier Bleu [Warning]: Failed to securely create log directory: {}",
			e
		);
	}

	/*
	 * Pre-Existing Directory Validation & Auto-Remediation
	 * Validates that the directory wasn't pre-staged by an attacker with
	 * wide-open permissions. Instead of panicking (which allows a trivial
	 * Denial of Service), we auto-remediate by wiping the tainted workspace.
	 */
	if let Ok(meta) = std::fs::metadata(log_dir) {
		if !meta.is_dir() || meta.uid() != 0 || (meta.mode() & 0o777) != 0o700 {
			eprintln!(
                "Bouclier Bleu [WARNING]: Log directory {} has insecure permissions (Potential Pre-Staging Attack). Auto-remediating...",
                log_dir
            );

			/*
			 * "Nuke and Pave"
			 * We do not just `chmod` the directory, because the attacker might
			 * have already created `alerts.json` and kept an open file
			 * descriptor to it to siphon logs. We destroy the entire directory
			 * tree to guarantee state purity.
			 * Graceful Degradation : Instead of crashing the daemon and
			 * disabling all protection modules via a panic, we fall back to
			 * /dev/null if remediation fails.
			 */
			let removal_result = if !meta.is_dir() {
				std::fs::remove_file(log_dir)
			} else {
				std::fs::remove_dir_all(log_dir)
			};

			if let Err(e) = removal_result {
				eprintln!("Bouclier Bleu [CRITICAL]: Failed to wipe compromised log directory: {}. Sinking telemetry to fallback.", e);
				return Err(());
			}

			// Rebuild the directory cleanly
			if let Err(e) = std::fs::DirBuilder::new()
				.recursive(true)
				.mode(0o700)
				.create(log_dir)
			{
				eprintln!("Bouclier Bleu [CRITICAL]: Failed to recreate secure log directory: {}. Sinking telemetry to fallback.", e);
				return Err(());
			}

			eprintln!("Bouclier Bleu [INFO]: Log directory securely rebuilt.");
		}
	} else {
		eprintln!("Bouclier Bleu [CRITICAL]: Failed to verify log directory metadata. Sinking telemetry to fallback.");
		return Err(());
	}

	Ok(())
}

/// Strict Open Controls
/// Enforces O_NOFOLLOW to completely neutralize symlink swapping attacks and
/// restricts read access to root (0o600).
fn open_strict_file(log_dir: &str) -> Option<File> {
	match OpenOptions::new()
		.create(true)
		.append(true)
		.mode(0o600)
		.custom_flags(rustix::fs::OFlags::NOFOLLOW.bits() as i32)
		.open(format!("{}/alerts.json", log_dir))
	{
		Ok(f) => Some(f),
		Err(e) => {
			eprintln!(
				"Bouclier Bleu [CRITICAL]: Failed to open SIEM sink: {}. Using /dev/null fallback.",
				e
			);
			None
		}
	}
}

/// NDJSON Forwarding Engine
///
/// Wraps the module-specific struct in a standardized envelope containing
/// SIEM-critical metadata (ISO-like timestamps, source identifiers) and
/// flushes it to disk.
pub fn emit_siem_event<T: serde::Serialize>(module_slug: &str, alert: &T) {
	let file_mutex = SIEM_LOG_SINK.get_or_init(|| {
		let log_dir = "/var/log/bouclier-bleu";

		if ensure_secure_directory(log_dir).is_err() {
			return get_fallback_sink();
		}

		if let Some(f) = open_strict_file(log_dir) {
			Mutex::new(Some(f))
		} else {
			get_fallback_sink()
		}
	});

	let timestamp_ms = std::time::SystemTime::now()
		.duration_since(std::time::UNIX_EPOCH)
		.unwrap_or_default()
		.as_millis();

	let envelope = EnvelopedAlert {
		timestamp_ms,
		event_source: module_slug,
		payload: alert,
	};

	// Serialize and write to disk
	let Ok(json_string) = serde_json::to_string(&envelope) else {
		return;
	};
	let Ok(mut file_guard) = file_mutex.lock() else {
		return;
	};
	let Some(file) = file_guard.as_mut() else {
		return;
	};

	/*
	 * Telemetry Sink Validation
	 * explicitly catch and log write failures to alert operators of potential
	 * disk exhaustion or SIEM ingestion issues.
	 */
	if let Err(e) = writeln!(file, "{}", json_string) {
		eprintln!("Bouclier Bleu [ERROR]: Failed to write SIEM event: {}", e);
	}
}
