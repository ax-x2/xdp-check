use colored::Colorize;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum CheckStatus {
    Pass,
    Fail,
    Warning,
    Info,
    Error,
}

impl CheckStatus {
    pub fn to_icon(&self) -> String {
        match self {
            CheckStatus::Pass => "✓".green().to_string(),
            CheckStatus::Fail => "✗".red().to_string(),
            CheckStatus::Warning => "⚠".yellow().to_string(),
            CheckStatus::Info => "ℹ".blue().to_string(),
            CheckStatus::Error => "!".red().bold().to_string(),
        }
    }

    #[allow(dead_code)]
    pub fn to_text(&self) -> String {
        match self {
            CheckStatus::Pass => "PASS".green().to_string(),
            CheckStatus::Fail => "FAIL".red().to_string(),
            CheckStatus::Warning => "WARN".yellow().to_string(),
            CheckStatus::Info => "INFO".blue().to_string(),
            CheckStatus::Error => "ERROR".red().bold().to_string(),
        }
    }

    pub fn is_failure(&self) -> bool {
        matches!(self, CheckStatus::Fail | CheckStatus::Error)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CheckResult {
    pub name: String,
    pub status: CheckStatus,
    pub message: String,
    pub details: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Report {
    sections: HashMap<String, Vec<CheckResult>>,
    #[serde(skip)]
    order: Vec<String>,
}

impl Report {
    pub fn new() -> Self {
        Self {
            sections: HashMap::new(),
            order: Vec::new(),
        }
    }

    pub fn add_section(&mut self, name: &str, results: Vec<CheckResult>) {
        self.order.push(name.to_string());
        self.sections.insert(name.to_string(), results);
    }

    pub fn is_compatible(&self) -> bool {
        !self.sections.values()
            .flatten()
            .any(|r| r.status.is_failure())
    }

    pub fn print_human(&self, verbose: bool) {
        let mut has_failures = false;
        let mut has_warnings = false;

        for section_name in &self.order {
            if let Some(results) = self.sections.get(section_name) {
                println!();
                println!("{}", section_name.cyan().bold());
                println!("{}", "-".repeat(section_name.len()).cyan());

                for result in results {
                    // Format the main line
                    println!(
                        "  {} {} - {}",
                        result.status.to_icon(),
                        result.name.bold(),
                        result.message
                    );

                    if let Some(ref details) = result.details {
                        if verbose || matches!(result.status, CheckStatus::Fail | CheckStatus::Warning | CheckStatus::Error) {
                            for line in details.lines() {
                                println!("      {}", line.dimmed());
                            }
                        }
                    }

                    if result.status.is_failure() {
                        has_failures = true;
                    }
                    if matches!(result.status, CheckStatus::Warning) {
                        has_warnings = true;
                    }
                }
            }
        }

        // Print summary
        println!();
        println!("{}", "=".repeat(50).cyan());
        println!("{}", "Summary".cyan().bold());
        println!("{}", "=".repeat(50).cyan());

        if has_failures {
            println!("{}", "❌ XDP compatibility check FAILED".red().bold());
            println!("{}", "   Some critical requirements are not met.".red());
            println!("{}", "   Please address the issues marked with ✗ above.".red());
        } else if has_warnings {
            println!("{}", "⚠️  XDP compatibility check PASSED with warnings".yellow().bold());
            println!("{}", "   System supports XDP but some optimizations are missing.".yellow());
            println!("{}", "   Review warnings marked with ⚠ for better performance.".yellow());
        } else {
            println!("{}", "✅ XDP compatibility check PASSED".green().bold());
            println!("{}", "   System is ready for XDP deployment!".green());
        }

        // Additional tips
        if !verbose && (has_failures || has_warnings) {
            println!();
            println!("{}", "💡 Run with --verbose for detailed information".dimmed());
        }
    }

    pub fn print_json(&self) -> anyhow::Result<()> {
        let summary = ReportSummary {
            compatible: self.is_compatible(),
            sections: self.sections.clone(),
            check_counts: self.check_counts(),
        };

        println!("{}", serde_json::to_string_pretty(&summary)?);
        Ok(())
    }

    fn check_counts(&self) -> CheckCounts {
        let mut counts = CheckCounts::default();

        for results in self.sections.values() {
            for result in results {
                match result.status {
                    CheckStatus::Pass => counts.pass += 1,
                    CheckStatus::Fail => counts.fail += 1,
                    CheckStatus::Warning => counts.warning += 1,
                    CheckStatus::Info => counts.info += 1,
                    CheckStatus::Error => counts.error += 1,
                }
            }
        }

        counts
    }
}

#[derive(Debug, Serialize, Deserialize, Default)]
struct CheckCounts {
    pass: usize,
    fail: usize,
    warning: usize,
    info: usize,
    error: usize,
}

#[derive(Debug, Serialize, Deserialize)]
struct ReportSummary {
    compatible: bool,
    check_counts: CheckCounts,
    sections: HashMap<String, Vec<CheckResult>>,
}