use anyhow::{Context, Result};
use std::fs;
use std::path::Path;
use nix::sys::resource;

use crate::output::{CheckResult, CheckStatus};

pub fn check_system_resources() -> Result<Vec<CheckResult>> {
    let mut results = Vec::new();

    results.push(check_huge_pages()?);

    results.push(check_memlock_limit()?);

    results.extend(check_cpu_info()?);

    results.push(check_irq_affinity());

    results.push(check_system_load()?);

    Ok(results)
}

fn check_huge_pages() -> Result<CheckResult> {
    let hugepage_2mb_path = "/sys/kernel/mm/hugepages/hugepages-2048kB/free_hugepages";
    let hugepage_1gb_path = "/sys/kernel/mm/hugepages/hugepages-1048576kB/free_hugepages";

    let mut huge_2mb = 0;
    let mut huge_1gb = 0;

    if Path::new(hugepage_2mb_path).exists() {
        if let Ok(content) = fs::read_to_string(hugepage_2mb_path) {
            huge_2mb = content.trim().parse::<usize>().unwrap_or(0);
        }
    }

    if Path::new(hugepage_1gb_path).exists() {
        if let Ok(content) = fs::read_to_string(hugepage_1gb_path) {
            huge_1gb = content.trim().parse::<usize>().unwrap_or(0);
        }
    }

    let status = if huge_2mb > 0 || huge_1gb > 0 {
        CheckStatus::Pass
    } else {
        CheckStatus::Info
    };

    let message = if huge_1gb > 0 && huge_2mb > 0 {
        format!("2MB: {}, 1GB: {} pages available", huge_2mb, huge_1gb)
    } else if huge_2mb > 0 {
        format!("{} x 2MB huge pages available", huge_2mb)
    } else if huge_1gb > 0 {
        format!("{} x 1GB huge pages available", huge_1gb)
    } else {
        "No huge pages available".to_string()
    };

    Ok(CheckResult {
        name: "Huge Pages".to_string(),
        status,
        message,
        details: match status {
            CheckStatus::Pass => Some("Huge pages improve XDP performance by reducing TLB misses".to_string()),
            _ => Some("XDP will use regular 4KB pages. Consider enabling huge pages for better performance.".to_string()),
        },
    })
}

fn check_memlock_limit() -> Result<CheckResult> {
    let rlimit = resource::getrlimit(resource::Resource::RLIMIT_MEMLOCK)?;

    let cur_limit_mb = rlimit.0 / (1024 * 1024);
    let max_limit_mb = rlimit.1 / (1024 * 1024);

    let status = if rlimit.0 == nix::libc::RLIM_INFINITY || cur_limit_mb >= 512 {
        CheckStatus::Pass
    } else if cur_limit_mb >= 64 {
        CheckStatus::Warning
    } else {
        CheckStatus::Fail
    };

    let message = if rlimit.0 == nix::libc::RLIM_INFINITY {
        "Unlimited memory lock".to_string()
    } else {
        format!("Current: {} MB, Max: {} MB", cur_limit_mb,
            if rlimit.1 == nix::libc::RLIM_INFINITY {
                "unlimited".to_string()
            } else {
                format!("{}", max_limit_mb)
            })
    };

    Ok(CheckResult {
        name: "Memory Lock Limit".to_string(),
        status,
        message,
        details: match status {
            CheckStatus::Pass => Some("Sufficient memory lock limit for XDP".to_string()),
            CheckStatus::Warning => Some("Memory lock limit may be insufficient for large XDP deployments. Consider increasing with 'ulimit -l'.".to_string()),
            CheckStatus::Fail => Some("Memory lock limit too low for XDP. Increase with 'ulimit -l unlimited' or edit /etc/security/limits.conf.".to_string()),
            _ => None,
        },
    })
}

fn check_cpu_info() -> Result<Vec<CheckResult>> {
    let mut results = Vec::new();

    // Get CPU count
    let cpu_count = num_cpus();
    results.push(CheckResult {
        name: "CPU Cores".to_string(),
        status: CheckStatus::Info,
        message: format!("{} CPU cores available", cpu_count),
        details: Some("More cores allow processing XDP on multiple queues".to_string()),
    });

    let governor_path = "/sys/devices/system/cpu/cpu0/cpufreq/scaling_governor";
    if Path::new(governor_path).exists() {
        if let Ok(governor) = fs::read_to_string(governor_path) {
            let governor = governor.trim();
            let status = match governor {
                "performance" => CheckStatus::Pass,
                "powersave" | "conservative" => CheckStatus::Warning,
                _ => CheckStatus::Info,
            };

            results.push(CheckResult {
                name: "CPU Governor".to_string(),
                status,
                message: format!("CPU frequency governor: {}", governor),
                details: match governor {
                    "performance" => Some("Optimal for XDP performance".to_string()),
                    "powersave" | "conservative" => Some("Consider switching to 'performance' governor for better XDP throughput".to_string()),
                    _ => None,
                },
            });
        }
    }

    // isolated cores
    let isolated_path = "/sys/devices/system/cpu/isolated";
    if Path::new(isolated_path).exists() {
        if let Ok(isolated) = fs::read_to_string(isolated_path) {
            let isolated = isolated.trim();
            if !isolated.is_empty() && isolated != "\n" {
                results.push(CheckResult {
                    name: "Isolated CPUs".to_string(),
                    status: CheckStatus::Pass,
                    message: format!("Isolated CPUs: {}", isolated),
                    details: Some("Isolated CPUs can be dedicated to XDP processing".to_string()),
                });
            }
        }
    }

    Ok(results)
}

fn check_irq_affinity() -> CheckResult {
    // check if irqbalance is running
    let irqbalance_running = std::process::Command::new("pgrep")
        .arg("irqbalance")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false);

    if irqbalance_running {
        CheckResult {
            name: "IRQ Balance".to_string(),
            status: CheckStatus::Info,
            message: "irqbalance service is running".to_string(),
            details: Some("Consider stopping irqbalance and manually setting IRQ affinity for XDP NICs".to_string()),
        }
    } else {
        CheckResult {
            name: "IRQ Balance".to_string(),
            status: CheckStatus::Pass,
            message: "irqbalance is not running".to_string(),
            details: Some("Manual IRQ affinity configuration recommended for optimal XDP performance".to_string()),
        }
    }
}

/// check system load
fn check_system_load() -> Result<CheckResult> {
    let loadavg = fs::read_to_string("/proc/loadavg")
        .context("Failed to read /proc/loadavg")?;

    let parts: Vec<&str> = loadavg.split_whitespace().collect();
    if parts.len() < 3 {
        return Ok(CheckResult {
            name: "System Load".to_string(),
            status: CheckStatus::Warning,
            message: "Unable to determine system load".to_string(),
            details: None,
        });
    }

    let load1: f64 = parts[0].parse().unwrap_or(0.0);
    let cpu_count = num_cpus() as f64;

    let load_ratio = load1 / cpu_count;

    let status = if load_ratio < 0.7 {
        CheckStatus::Pass
    } else if load_ratio < 0.9 {
        CheckStatus::Warning
    } else {
        CheckStatus::Warning
    };

    Ok(CheckResult {
        name: "System Load".to_string(),
        status,
        message: format!("Load average: {} ({}% of {} cores)", load1, (load_ratio * 100.0) as i32, cpu_count as i32),
        details: match status {
            CheckStatus::Pass => Some("System has capacity for XDP processing".to_string()),
            CheckStatus::Warning => Some("System is under load. XDP performance may be affected.".to_string()),
            _ => None,
        },
    })
}

fn num_cpus() -> usize {
    std::thread::available_parallelism()
        .map(|p| p.get())
        .unwrap_or(1)
}