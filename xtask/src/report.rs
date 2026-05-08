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

use crate::utils::project_root;
use std::fs;
use std::time::Duration;

/// Execution Envelope Data Structure
///
/// Standardizes the schema for tracking test execution across boundaries.
/// This flat structure makes aggregating CI/CD reports significantly easier.
pub struct TestRecord {
	pub name: String,
	pub category: String,
	pub duration: Duration,
	pub passed: bool,
}

/// Markdown Artifact Generator
///
/// Translates the raw telemetry array into a human-readable and CI-friendly
/// Markdown report (`tests/Results.md`). This allows GitHub Actions or other
/// pipelines to ingest execution summaries easily.
pub fn generate_markdown_report(
	results: &[TestRecord],
	setup_time: Duration,
	restore_time: Duration,
) -> Result<(), std::io::Error> {
	if results.is_empty() {
		println!("[INFO] No tests were executed. Skipping report generation.");
		return Ok(());
	}

	let mut report = String::from(
		"# Bouclier Bleu Test Results\n\n| Test Name | Category | Duration | Status |\n|-----------|----------|----------|--------|\n",
	);

	for res in results {
		report.push_str(&format!(
			"| `{}` | {} | {:.2}s | {} |\n",
			res.name,
			res.category,
			res.duration.as_secs_f64(),
			if res.passed { "PASS" } else { "FAIL" }
		));
	}

	/*
	 * Environment Latency Telemetry
	 * Captures the overall infrastructure tax (snapshot/restore times) to
	 * benchmark and optimize the testing runner's internal efficiency over
	 * time.
	 */
	report.push_str(&format!(
		"\n## Pipeline Environment Metrics\n\n* **Initial VM Setup & Snapshot:** `{:.2}s`\n* **Cumulative Snapshot Restorations:** `{:.2}s`\n",
		setup_time.as_secs_f64(),
		restore_time.as_secs_f64()
	));

	// Aggregating side-loaded benchmark results if generated
	let bench_path = project_root().join("tests").join("benchmark_results.md");
	if bench_path.exists() {
		if let Ok(bench_data) = fs::read_to_string(&bench_path) {
			report.push('\n');
			report.push_str(&bench_data);
		}
		let _ = fs::remove_file(&bench_path);
	}

	let report_path = project_root().join("tests").join("Results.md");
	fs::write(&report_path, report)?;

	println!(
		"\n[INFO] Test report successfully generated at {}",
		report_path.display()
	);
	Ok(())
}
