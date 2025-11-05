use anyhow::Result;
use caps::{CapSet, Capability};
use nix::unistd::geteuid;
use nix::sys::utsname;

use crate::output::{CheckResult, CheckStatus};

pub fn check_capabilities() -> Result<Vec<CheckResult>> {
    let mut results = Vec::new();

    let is_root = geteuid().is_root();

    results.push(CheckResult {
        name: "user Privileges".to_string(),
        status: if is_root { CheckStatus::Pass } else { CheckStatus::Info },
        message: if is_root {
            "running as root".to_string()
        } else {
            format!("running as user (UID: {})", geteuid())
        },
        details: if !is_root {
            Some("non-root users need specific capabilities for XDP".to_string())
        } else {
            None
        },
    });

    // check kernel version to determine which capabilities model to use
    let uname = utsname::uname()?;
    let release = uname.release().to_str().unwrap_or("unknown");
    let parts: Vec<&str> = release.split(&['.', '-'][..]).collect();
    let major: u32 = if parts.len() > 0 { parts[0].parse().unwrap_or(0) } else { 0 };
    let minor: u32 = if parts.len() > 1 { parts[1].parse().unwrap_or(0) } else { 0 };

    let kernel_5_8_plus = major > 5 || (major == 5 && minor >= 8);

    let mut required_caps = vec![
        (Capability::CAP_NET_RAW, "Raw socket operations"),
        (Capability::CAP_NET_ADMIN, "Network administration"),
    ];

    if kernel_5_8_plus {
        required_caps.push((Capability::CAP_BPF, "BPF operations"));
        required_caps.push((Capability::CAP_PERFMON, "Performance monitoring"));
    } else {
        required_caps.push((Capability::CAP_SYS_ADMIN, "System administration (for BPF on older kernels)"));
    }

    let effective_caps = caps::read(None, CapSet::Effective)?;

    for (cap, description) in &required_caps {
        let has_cap = effective_caps.contains(cap);

        let status = if has_cap {
            CheckStatus::Pass
        } else if is_root {
            CheckStatus::Warning
        } else {
            CheckStatus::Fail
        };

        results.push(CheckResult {
            name: format!("{:?}", cap),
            status,
            message: description.to_string(),
            details: match status {
                CheckStatus::Pass => Some("Capability granted".to_string()),
                CheckStatus::Fail => Some(format!(
                    "Missing capability. Grant it with: sudo setcap cap_{}=ep <binary>",
                    format!("{:?}", cap).to_lowercase().replace("cap_", "")
                )),
                CheckStatus::Warning => Some("Root user but capability not detected (unusual)".to_string()),
                _ => None,
            },
        });
    }

    let permitted_caps = caps::read(None, CapSet::Permitted)?;
    let mut available_but_not_effective = Vec::new();

    for (cap, _) in &required_caps {
        if permitted_caps.contains(cap) && !effective_caps.contains(cap) {
            available_but_not_effective.push(format!("{:?}", cap));
        }
    }

    if !available_but_not_effective.is_empty() {
        results.push(CheckResult {
            name: "Available Capabilities".to_string(),
            status: CheckStatus::Info,
            message: "Some capabilities are permitted but not effective".to_string(),
            details: Some(format!(
                "Could activate: {}. Consider using ambient capabilities.",
                available_but_not_effective.join(", ")
            )),
        });
    }

    Ok(results)
}

pub fn quick_capability_check() -> Result<Vec<CheckResult>> {
    let mut results = Vec::new();

    let is_root = geteuid().is_root();
    let effective_caps = caps::read(None, CapSet::Effective)?;

    // essential caps
    let has_net_admin = effective_caps.contains(&Capability::CAP_NET_ADMIN);
    let has_net_raw = effective_caps.contains(&Capability::CAP_NET_RAW);
    let has_bpf_or_admin = effective_caps.contains(&Capability::CAP_BPF)
        || effective_caps.contains(&Capability::CAP_SYS_ADMIN);

    let status = if is_root || (has_net_admin && has_net_raw && has_bpf_or_admin) {
        CheckStatus::Pass
    } else if has_net_admin || has_net_raw {
        CheckStatus::Warning
    } else {
        CheckStatus::Fail
    };

    results.push(CheckResult {
        name: "XDP Capabilities".to_string(),
        status,
        message: if is_root {
            "Running as root (all capabilities)".to_string()
        } else {
            "Checking essential capabilities".to_string()
        },
        details: match status {
            CheckStatus::Pass => Some("All required capabilities present".to_string()),
            CheckStatus::Warning => Some("Some capabilities missing. XDP may work with limitations.".to_string()),
            CheckStatus::Fail => Some("Missing critical capabilities. XDP will not work.".to_string()),
            _ => None,
        },
    });

    Ok(results)
}