use anyhow::Result;
use std::fs;
use std::path::Path;
use aya::programs::loaded_programs;

use crate::output::{CheckResult, CheckStatus};

pub fn check_xdp_runtime(interface: Option<&str>) -> Result<Vec<CheckResult>> {
    let mut results = Vec::new();

    if let Some(iface) = interface {
        results.extend(check_interface_xdp_runtime(iface)?);
    } else {
        results.extend(check_all_xdp_runtime()?);
    }

    results.push(check_xsk_sockets());

    results.extend(check_bpf_programs()?);

    Ok(results)
}

fn check_all_xdp_runtime() -> Result<Vec<CheckResult>> {
    Ok(Vec::new())
}

fn check_interface_xdp_runtime(interface: &str) -> Result<Vec<CheckResult>> {
    let mut results = Vec::new();

    log::debug!("Checking XDP runtime for interface: {}", interface);

    // Check if interface exists
    let iface_path = format!("/sys/class/net/{}", interface);
    if !Path::new(&iface_path).exists() {
        results.push(CheckResult {
            name: format!("{}: Interface", interface),
            status: CheckStatus::Warning,
            message: "Interface not found".to_string(),
            details: Some(format!("Network interface '{}' does not exist", interface)),
        });
        return Ok(results);
    }

    // Query all XDP programs to see if any are loaded
    let xdp_programs: Vec<_> = loaded_programs()
        .filter_map(|r| r.ok())
        .filter(|p| {
            matches!(p.program_type(), Ok(aya::programs::ProgramType::Xdp))
        })
        .collect();

    if xdp_programs.is_empty() {
        results.push(CheckResult {
            name: format!("{}: XDP Program", interface),
            status: CheckStatus::Info,
            message: "No XDP programs loaded in the system".to_string(),
            details: None,
        });
        return Ok(results);
    }

    // Find agave_xdp programs
    let agave_programs: Vec<_> = xdp_programs
        .iter()
        .filter(|p| p.name_as_str().unwrap_or("") == "agave_xdp")
        .collect();

    if !agave_programs.is_empty() {
        for prog in agave_programs {
            let tag = format!("{:016x}", prog.tag());
            results.push(CheckResult {
                name: format!("{}: XDP Program", interface),
                status: CheckStatus::Pass,
                message: format!("agave_xdp program loaded (ID: {})", prog.id()),
                details: Some(format!("Program Tag: {}\nType: XDP", tag)),
            });
        }
    } else {
        results.push(CheckResult {
            name: format!("{}: XDP Program", interface),
            status: CheckStatus::Warning,
            message: format!("{} XDP program(s) loaded, but none named 'agave_xdp'", xdp_programs.len()),
            details: Some("Other XDP programs found but 'agave_xdp' is not loaded".to_string()),
        });
    }

    Ok(results)
}

fn check_xsk_sockets() -> CheckResult {
    // /proc/net/xsk for AF_XDP socket information
    let xsk_path = "/proc/net/xsk";

    if Path::new(xsk_path).exists() {
        if let Ok(content) = fs::read_to_string(xsk_path) {
            let lines: Vec<&str> = content.lines().collect();
            if lines.len() > 1 {  // header
                return CheckResult {
                    name: "AF_XDP Sockets".to_string(),
                    status: CheckStatus::Pass,
                    message: format!("{} AF_XDP socket(s) active", lines.len() - 1),
                    details: Some("Active AF_XDP sockets detected".to_string()),
                };
            }
        }
    }

    // alternative check: look for xsk_diag module
    if let Ok(modules) = fs::read_to_string("/proc/modules") {
        if modules.contains("xsk_diag") {
            return CheckResult {
                name: "AF_XDP Support".to_string(),
                status: CheckStatus::Info,
                message: "XSK diagnostic module loaded".to_string(),
                details: Some("AF_XDP support available but no active sockets".to_string()),
            };
        }
    }

    CheckResult {
        name: "AF_XDP Sockets".to_string(),
        status: CheckStatus::Info,
        message: "No AF_XDP sockets detected".to_string(),
        details: Some("AF_XDP socket monitoring may not be available".to_string()),
    }
}

/// Check for BPF programs
fn check_bpf_programs() -> Result<Vec<CheckResult>> {
    let mut results = Vec::new();

    log::debug!("Querying loaded XDP programs via aya");

    // Use aya to list XDP programs
    let xdp_programs: Vec<_> = loaded_programs()
        .filter_map(|r| r.ok())
        .filter(|p| {
            matches!(p.program_type(), Ok(aya::programs::ProgramType::Xdp))
        })
        .collect();

    log::debug!("Found {} XDP program(s)", xdp_programs.len());

    // Find agave_xdp programs
    let agave_programs: Vec<_> = xdp_programs
        .iter()
        .filter(|p| p.name_as_str().unwrap_or("") == "agave_xdp")
        .collect();

    // Report on agave_xdp programs
    if !agave_programs.is_empty() {
        for prog in &agave_programs {
            let tag = format!("{:016x}", prog.tag());
            let details = format!(
                "Program ID: {}\nProgram Tag: {}\nType: XDP",
                prog.id(),
                tag
            );

            results.push(CheckResult {
                name: "Agave XDP Program".to_string(),
                status: CheckStatus::Pass,
                message: format!("agave_xdp is loaded and active (ID: {})", prog.id()),
                details: Some(details),
            });

            log::debug!("  ✓ agave_xdp: ID {} tag {}", prog.id(), tag);
        }
    } else if !xdp_programs.is_empty() {
        // Other XDP programs exist but no agave_xdp
        results.push(CheckResult {
            name: "Agave XDP Program".to_string(),
            status: CheckStatus::Warning,
            message: format!("{} XDP program(s) loaded, but none named 'agave_xdp'", xdp_programs.len()),
            details: Some("Other XDP programs detected but 'agave_xdp' not found".to_string()),
        });

        for prog in &xdp_programs {
            log::debug!("  - Other XDP Program: ID {} name '{}'",
                prog.id(),
                prog.name_as_str().unwrap_or("?")
            );
        }
    } else {
        // No XDP programs at all
        results.push(CheckResult {
            name: "Agave XDP Program".to_string(),
            status: CheckStatus::Info,
            message: "No XDP programs currently loaded".to_string(),
            details: None,
        });
    }

    // check /sys/fs/bpf for pinned programs
    let bpf_fs = "/sys/fs/bpf";
    if Path::new(bpf_fs).exists() {
        let mut pinned_count = 0;
        if let Ok(entries) = fs::read_dir(bpf_fs) {
            for entry in entries.flatten() {
                if let Some(name) = entry.file_name().to_str() {
                    if name.contains("xdp") || name.contains("xsk") {
                        pinned_count += 1;
                    }
                }
            }
        }

        if pinned_count > 0 {
            results.push(CheckResult {
                name: "Pinned BPF Programs".to_string(),
                status: CheckStatus::Info,
                message: format!("{} XDP-related pinned program(s)", pinned_count),
                details: Some(format!("Found in {}", bpf_fs)),
            });
        }
    }

    // check if BPF filesystem is mounted
    if let Ok(mounts) = fs::read_to_string("/proc/mounts") {
        if mounts.contains("bpf") {
            results.push(CheckResult {
                name: "BPF Filesystem".to_string(),
                status: CheckStatus::Pass,
                message: "BPF filesystem mounted".to_string(),
                details: Some("BPF filesystem is available for pinning programs".to_string()),
            });
        }
    }

    Ok(results)
}