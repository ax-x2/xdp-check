use anyhow::Result;
use std::fs;
use std::path::Path;

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
    let mut results = Vec::new();
    let mut xdp_active = Vec::new();
    let mut xdp_inactive = Vec::new();

    for entry in fs::read_dir("/sys/class/net")? {
        if let Ok(entry) = entry {
            if let Some(name) = entry.file_name().to_str() {
                if name == "lo" {
                    continue;
                }

                let xdp_prog_path = format!("/sys/class/net/{}/xdp/prog_id", name);
                if Path::new(&xdp_prog_path).exists() {
                    if let Ok(prog_id) = fs::read_to_string(&xdp_prog_path) {
                        let prog_id = prog_id.trim();
                        if prog_id != "0" && !prog_id.is_empty() {
                            xdp_active.push(format!("{} (prog_id: {})", name, prog_id));
                        } else {
                            xdp_inactive.push(name.to_string());
                        }
                    }
                } else {
                    xdp_inactive.push(name.to_string());
                }
            }
        }
    }

    let status = if !xdp_active.is_empty() {
        CheckStatus::Pass
    } else {
        CheckStatus::Info
    };

    results.push(CheckResult {
        name: "Active XDP Programs".to_string(),
        status,
        message: format!("{} interface(s) with XDP programs", xdp_active.len()),
        details: if !xdp_active.is_empty() {
            Some(format!("Active on: {}", xdp_active.join(", ")))
        } else {
            Some("No XDP programs currently attached to any interface".to_string())
        },
    });

    Ok(results)
}

fn check_interface_xdp_runtime(interface: &str) -> Result<Vec<CheckResult>> {
    let mut results = Vec::new();

    let xdp_prog_path = format!("/sys/class/net/{}/xdp/prog_id", interface);

    if Path::new(&xdp_prog_path).exists() {
        if let Ok(prog_id) = fs::read_to_string(&xdp_prog_path) {
            let prog_id = prog_id.trim();
            if prog_id != "0" && !prog_id.is_empty() {
                results.push(CheckResult {
                    name: format!("{}: XDP Program", interface),
                    status: CheckStatus::Pass,
                    message: format!("XDP program active (ID: {})", prog_id),
                    details: Some("XDP program is currently attached and running".to_string()),
                });

                // Try to get more info about the program
                let prog_info = bpf_prog_info(prog_id);
                if let Some(info) = prog_info {
                    results.push(CheckResult {
                        name: format!("{}: XDP Program Info", interface),
                        status: CheckStatus::Info,
                        message: "Program details".to_string(),
                        details: Some(info),
                    });
                }
            } else {
                results.push(CheckResult {
                    name: format!("{}: XDP Program", interface),
                    status: CheckStatus::Info,
                    message: "No XDP program attached".to_string(),
                    details: None,
                });
            }
        }
    } else {
        results.push(CheckResult {
            name: format!("{}: XDP Runtime", interface),
            status: CheckStatus::Warning,
            message: "Unable to check XDP status".to_string(),
            details: Some("XDP status file not found. Interface may not support XDP.".to_string()),
        });
    }

    // XDP mode (native/generic/offload)
    let xdp_mode_path = format!("/sys/class/net/{}/xdp/mode", interface);
    if Path::new(&xdp_mode_path).exists() {
        if let Ok(mode) = fs::read_to_string(&xdp_mode_path) {
            let mode = mode.trim();
            let mode_status = match mode {
                "native" | "driver" => CheckStatus::Pass,
                "generic" | "skb" => CheckStatus::Warning,
                "offload" | "hw" => CheckStatus::Pass,
                _ => CheckStatus::Info,
            };

            results.push(CheckResult {
                name: format!("{}: XDP Mode", interface),
                status: mode_status,
                message: format!("XDP mode: {}", mode),
                details: match mode {
                    "native" | "driver" => Some("Native/Driver mode - best performance".to_string()),
                    "generic" | "skb" => Some("Generic/SKB mode - slower, fallback mode".to_string()),
                    "offload" | "hw" => Some("Hardware offload - NIC processes XDP".to_string()),
                    _ => None,
                },
            });
        }
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

    // check if bpftool is available for detailed info
    let bpftool_available = std::process::Command::new("which")
        .arg("bpftool")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false);

    if bpftool_available {
        // try to list XDP programs using bpftool
        if let Ok(output) = std::process::Command::new("bpftool")
            .args(&["prog", "list", "type", "xdp"])
            .output()
        {
            if output.status.success() {
                let output_str = String::from_utf8_lossy(&output.stdout);
                let prog_count = output_str.lines().count();

                results.push(CheckResult {
                    name: "BPF Programs (XDP)".to_string(),
                    status: if prog_count > 0 { CheckStatus::Pass } else { CheckStatus::Info },
                    message: format!("{} XDP program(s) loaded", prog_count),
                    details: if prog_count > 0 {
                        Some("Use 'bpftool prog list type xdp' for details".to_string())
                    } else {
                        None
                    },
                });
            }
        }
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

/// BPF program info (if available)
fn bpf_prog_info(prog_id: &str) -> Option<String> {
    // try to get program info from /proc/self/fdinfo if we have access
    // alternatrive: check if bpftool is available
    if let Ok(output) = std::process::Command::new("bpftool")
        .args(&["prog", "show", "id", prog_id])
        .output()
    {
        if output.status.success() {
            let info = String::from_utf8_lossy(&output.stdout);
            if !info.is_empty() {
                return Some(info.lines().next()?.to_string());
            }
        }
    }

    None
}