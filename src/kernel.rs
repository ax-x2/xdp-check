use anyhow::{Context, Result};
use std::fs;
use std::path::Path;
use nix::sys::utsname;

use crate::output::{CheckResult, CheckStatus};

/// min means it will not work
const MIN_KERNEL_VERSION: (u32, u32) = (4, 18);
/// avoid older kernels and move to 6.xx.x
const RECOMMENDED_KERNEL_VERSION: (u32, u32) = (6, 10);

pub fn check_kernel_compatibility() -> Result<Vec<CheckResult>> {
    let mut results = Vec::new();

    results.push(check_kernel_version()?);

    results.extend(check_kernel_config()?);

    results.push(check_btf_support());

    results.extend(check_kernel_modules()?);

    Ok(results)
}

/// version only
pub fn quick_kernel_check() -> Result<Vec<CheckResult>> {
    Ok(vec![check_kernel_version()?])
}

fn check_kernel_version() -> Result<CheckResult> {
    let uname = utsname::uname()?;
    let release = uname.release().to_str().unwrap_or("unknown");

    // parse kernel version (e.g., "x.xx.x-xx-generic" -> (5, 15, 0))
    let parts: Vec<&str> = release.split(&['.', '-'][..]).collect();
    if parts.len() < 2 {
        return Ok(CheckResult {
            name: "Kernel Version".to_string(),
            status: CheckStatus::Error,
            message: format!("Unable to parse kernel version: {}", release),
            details: None,
        });
    }

    let major: u32 = parts[0].parse().unwrap_or(0);
    let minor: u32 = parts[1].parse().unwrap_or(0);

    let status = if major > MIN_KERNEL_VERSION.0
        || (major == MIN_KERNEL_VERSION.0 && minor >= MIN_KERNEL_VERSION.1) {
        if major > RECOMMENDED_KERNEL_VERSION.0
            || (major == RECOMMENDED_KERNEL_VERSION.0 && minor >= RECOMMENDED_KERNEL_VERSION.1) {
            CheckStatus::Pass
        } else {
            CheckStatus::Warning
        }
    } else {
        CheckStatus::Fail
    };

    let message = format!("Kernel version: {} ({}.{})", release, major, minor);
    let details = match status {
        CheckStatus::Pass => Some(format!(
            "Kernel {}.{} meets recommended version {}.{} for stable AF_XDP support",
            major, minor, RECOMMENDED_KERNEL_VERSION.0, RECOMMENDED_KERNEL_VERSION.1
        )),
        CheckStatus::Warning => Some(format!(
            "Kernel {}.{} supports AF_XDP but {}.{}+ is recommended for better stability",
            major, minor, RECOMMENDED_KERNEL_VERSION.0, RECOMMENDED_KERNEL_VERSION.1
        )),
        CheckStatus::Fail => Some(format!(
            "Kernel {}.{} is too old. Minimum required: {}.{}",
            major, minor, MIN_KERNEL_VERSION.0, MIN_KERNEL_VERSION.1
        )),
        _ => None,
    };

    Ok(CheckResult {
        name: "Kernel Version".to_string(),
        status,
        message,
        details,
    })
}

fn check_kernel_config() -> Result<Vec<CheckResult>> {
    let mut results = Vec::new();

    // different kernel config locations
    let config_paths = [
        format!("/boot/config-{}", utsname::uname()?.release().to_str().unwrap_or("")),
        "/proc/config.gz".to_string(),
        "/boot/config".to_string(),
    ];

    let mut config_content = None;
    let mut config_path = None;

    for path in &config_paths {
        if Path::new(path).exists() {
            if path.ends_with(".gz") {
                // Handle compressed config
                use std::process::Command;
                let output = Command::new("zcat")
                    .arg(path)
                    .output()
                    .context("Failed to decompress kernel config")?;

                if output.status.success() {
                    config_content = Some(String::from_utf8_lossy(&output.stdout).to_string());
                    config_path = Some(path.clone());
                    break;
                }
            } else {
                match fs::read_to_string(path) {
                    Ok(content) => {
                        config_content = Some(content);
                        config_path = Some(path.clone());
                        break;
                    }
                    Err(_) => continue,
                }
            }
        }
    }

    if config_content.is_none() {
        results.push(CheckResult {
            name: "Kernel Config".to_string(),
            status: CheckStatus::Warning,
            message: "Unable to find kernel configuration file".to_string(),
            details: Some("Cannot verify XDP-related kernel options. They might still be enabled.".to_string()),
        });
        return Ok(results);
    }

    let config = config_content.unwrap();
    let source = config_path.unwrap();

    // Check required kernel options
    let required_options = [
        ("CONFIG_XDP_SOCKETS", "AF_XDP socket support"),
        ("CONFIG_BPF", "BPF subsystem"),
        ("CONFIG_BPF_SYSCALL", "BPF system call"),
        ("CONFIG_NET", "Networking support"),
    ];

    for (option, description) in &required_options {
        let enabled = config.contains(&format!("{}=y", option))
            || config.contains(&format!("{}=m", option));

        results.push(CheckResult {
            name: format!("{}", option),
            status: if enabled { CheckStatus::Pass } else { CheckStatus::Fail },
            message: description.to_string(),
            details: if enabled {
                Some(format!("Enabled in {}", source))
            } else {
                Some(format!("Not found or disabled in {}. Required for XDP.", source))
            },
        });
    }

    // optional but recommended options
    let optional_options = [
        ("CONFIG_DEBUG_INFO_BTF", "BTF type information"),
        ("CONFIG_NETLINK", "Netlink support for routing"),
    ];

    for (option, description) in &optional_options {
        let enabled = config.contains(&format!("{}=y", option))
            || config.contains(&format!("{}=m", option));

        results.push(CheckResult {
            name: format!("{}", option),
            status: if enabled { CheckStatus::Pass } else { CheckStatus::Warning },
            message: description.to_string(),
            details: if enabled {
                Some(format!("Enabled in {}", source))
            } else {
                Some(format!("Not enabled in {}. Recommended for better XDP support.", source))
            },
        });
    }

    Ok(results)
}

fn check_btf_support() -> CheckResult {
    let btf_path = "/sys/kernel/btf/vmlinux";

    if Path::new(btf_path).exists() {
        CheckResult {
            name: "BTF Support".to_string(),
            status: CheckStatus::Pass,
            message: "BTF type information available".to_string(),
            details: Some(format!("Found at {}", btf_path)),
        }
    } else {
        CheckResult {
            name: "BTF Support".to_string(),
            status: CheckStatus::Warning,
            message: "BTF type information not found".to_string(),
            details: Some("BTF improves eBPF program compatibility but is not strictly required".to_string()),
        }
    }
}

fn check_kernel_modules() -> Result<Vec<CheckResult>> {
    let mut results = Vec::new();

    // modules are loaded
    let modules_file = fs::read_to_string("/proc/modules")
        .context("Failed to read /proc/modules")?;

    // XSK module check (for AF_XDP diagnostics)
    let xsk_loaded = modules_file.contains("xsk");

    results.push(CheckResult {
        name: "XSK Module".to_string(),
        status: if xsk_loaded { CheckStatus::Pass } else { CheckStatus::Info },
        message: if xsk_loaded {
            "XSK diagnostic module loaded".to_string()
        } else {
            "XSK diagnostic module not loaded".to_string()
        },
        details: Some(if xsk_loaded {
            "Module is loaded for AF_XDP socket diagnostics".to_string()
        } else {
            "Optional module for AF_XDP diagnostics. Core functionality still works.".to_string()
        }),
    });

    Ok(results)
}