use anyhow::Result;
use std::fs;
use std::path::Path;
use std::os::unix::io::{AsRawFd, FromRawFd, OwnedFd};
use libc::{ifreq, socket, ioctl, AF_INET, SOCK_DGRAM, SIOCETHTOOL, IF_NAMESIZE};
use std::{mem, ptr};

use crate::output::{CheckResult, CheckStatus};

/// Known good drivers with XDP support
const GOOD_DRIVERS: &[&str] = &[
    "i40e",     // intel 40GbE (has bugs but widely used)
    "ixgbe",    // intel 10GbE
    "ice",      // intel E810 100GbE
    "igb",      // intel 1GbE
    "igc",      // intel 2.5GbE
    "mlx5_core", // mellanox ConnectX-4/5/6
    "mlx4_core", // mellanox ConnectX-3
    "nfp",      // netronome
    "bnxt_en",  // broadcom NetXtreme
    // "ena",      // amazon ENA
    // "veth",     // virtual ethernet (for testing)
    // "tun",      // TUN/TAP (limited support)
    // "virtio_net", // virtio network (with caveats)
];

/// Drivers with known issues
const PROBLEMATIC_DRIVERS: &[(&str, &str)] = &[
    ("i40e", "multi-fragment packet bugs - requires workaround in slowgave XDP"),
    // ("virtio_net", "limited XDP support, no zero-copy"),
    // ("tun", "generic XDP only, poor performance"),
];

/// ring buffer parameters from ethtool
#[repr(C)]
struct EthtoolRingParam {
    cmd: u32,
    rx_max_pending: u32,
    rx_mini_max_pending: u32,
    rx_jumbo_max_pending: u32,
    tx_max_pending: u32,
    rx_pending: u32,
    rx_mini_pending: u32,
    rx_jumbo_pending: u32,
    tx_pending: u32,
}

const ETHTOOL_GRINGPARAM: u32 = 0x00000010;

pub fn check_all_interfaces() -> Result<Vec<CheckResult>> {
    let mut results = Vec::new();

    // list of network interfaces
    let interfaces = network_interfaces()?;

    if interfaces.is_empty() {
        results.push(CheckResult {
            name: "Network Interfaces".to_string(),
            status: CheckStatus::Warning,
            message: "No network interfaces found".to_string(),
            details: Some("Unable to detect network interfaces".to_string()),
        });
        return Ok(results);
    }

    for iface in interfaces {
        if iface == "lo" {
            continue; // skip loopback
        }

        let iface_results = check_interface_internal(&iface)?;
        results.extend(iface_results);
    }

    Ok(results)
}

pub fn check_interface(interface: &str) -> Result<Vec<CheckResult>> {
    check_interface_internal(interface)
}

pub fn quick_interface_check() -> Result<Vec<CheckResult>> {
    let mut results = Vec::new();

    let interfaces = network_interfaces()?;
    let mut xdp_capable = Vec::new();
    let mut non_xdp = Vec::new();

    for iface in interfaces {
        if iface == "lo" {
            continue;
        }

        if let Ok(driver) = interface_driver(&iface) {
            if GOOD_DRIVERS.contains(&driver.as_str()) {
                xdp_capable.push(format!("{} ({})", iface, driver));
            } else {
                non_xdp.push(format!("{} ({})", iface, driver));
            }
        }
    }

    let status = if !xdp_capable.is_empty() {
        CheckStatus::Pass
    } else if !non_xdp.is_empty() {
        CheckStatus::Warning
    } else {
        CheckStatus::Fail
    };

    results.push(CheckResult {
        name: "XDP-capable Interfaces".to_string(),
        status,
        message: format!("Found {} XDP-capable interface(s)", xdp_capable.len()),
        details: if !xdp_capable.is_empty() {
            Some(format!("XDP-ready: {}", xdp_capable.join(", ")))
        } else if !non_xdp.is_empty() {
            Some(format!("Interfaces without native XDP: {}", non_xdp.join(", ")))
        } else {
            Some("No network interfaces detected".to_string())
        },
    });

    Ok(results)
}

fn check_interface_internal(interface: &str) -> Result<Vec<CheckResult>> {
    let mut results = Vec::new();

    let sys_path = format!("/sys/class/net/{}", interface);
    if !Path::new(&sys_path).exists() {
        results.push(CheckResult {
            name: format!("Interface: {}", interface),
            status: CheckStatus::Error,
            message: "Interface not found".to_string(),
            details: Some(format!("No such interface: {}", interface)),
        });
        return Ok(results);
    }

    let operstate = fs::read_to_string(format!("{}/operstate", sys_path))
        .unwrap_or_else(|_| "unknown".to_string())
        .trim()
        .to_string();

    results.push(CheckResult {
        name: format!("{}: Status", interface),
        status: if operstate == "up" { CheckStatus::Pass } else { CheckStatus::Info },
        message: format!("Interface state: {}", operstate),
        details: None,
    });

    let driver = interface_driver(interface)?;

    let driver_status = if GOOD_DRIVERS.contains(&driver.as_str()) {
        if driver == "i40e" {
            CheckStatus::Warning
        } else {
            CheckStatus::Pass
        }
    } else {
        CheckStatus::Warning
    };

    let mut driver_details = format!("Driver: {}", driver);

    for (problematic_driver, issue) in PROBLEMATIC_DRIVERS {
        if driver == *problematic_driver {
            driver_details = format!("Driver: {} - KNOWN ISSUE: {}", driver, issue);
            break;
        }
    }

    results.push(CheckResult {
        name: format!("{}: Driver", interface),
        status: driver_status,
        message: format!("Network driver: {}", driver),
        details: Some(driver_details),
    });

    let xdp_status = check_xdp_support(interface)?;
    results.push(xdp_status);

    let queues = interface_queues(interface)?;
    results.push(CheckResult {
        name: format!("{}: Queues", interface),
        status: CheckStatus::Info,
        message: format!("RX queues: {}, TX queues: {}", queues.0, queues.1),
        details: Some("Multiple queues enable multi-core XDP processing".to_string()),
    });

    // check ring buffer sizes using ethtool ioctl
    match ring_parameters_ethtool(interface) {
        Ok((rx, tx)) => {
            results.push(CheckResult {
                name: format!("{}: Ring Buffers", interface),
                status: CheckStatus::Info,
                message: format!("RX: {}, TX: {}", rx, tx),
                details: Some("Ring buffer size affects XDP performance and memory usage".to_string()),
            });
        }
        Err(_) => {
            // if ethtool fails, check sysfs as fallback
            results.push(CheckResult {
                name: format!("{}: Ring Buffers", interface),
                status: CheckStatus::Warning,
                message: "Unable to determine ring buffer sizes".to_string(),
                details: Some("Could not query ring parameters via ethtool".to_string()),
            });
        }
    }

    // check interface speed
    if let Ok(speed) = fs::read_to_string(format!("{}/speed", sys_path)) {
        let speed = speed.trim();
        if let Ok(speed_mbps) = speed.parse::<u32>() {
            results.push(CheckResult {
                name: format!("{}: Speed", interface),
                status: CheckStatus::Info,
                message: if speed_mbps >= 10000 {
                    format!("{} Gbps", speed_mbps / 1000)
                } else {
                    format!("{} Mbps", speed_mbps)
                },
                details: None,
            });
        }
    }

    // MTU
    if let Ok(mtu) = fs::read_to_string(format!("{}/mtu", sys_path)) {
        let mtu = mtu.trim();
        results.push(CheckResult {
            name: format!("{}: MTU", interface),
            status: CheckStatus::Info,
            message: format!("MTU: {} bytes", mtu),
            details: None,
        });
    }

    Ok(results)
}

fn network_interfaces() -> Result<Vec<String>> {
    let mut interfaces = Vec::new();

    for entry in fs::read_dir("/sys/class/net")? {
        if let Ok(entry) = entry {
            if let Some(name) = entry.file_name().to_str() {
                interfaces.push(name.to_string());
            }
        }
    }

    Ok(interfaces)
}

fn interface_driver(interface: &str) -> Result<String> {
    let driver_path = format!("/sys/class/net/{}/device/driver", interface);

    if let Ok(link) = fs::read_link(&driver_path) {
        if let Some(driver_name) = link.file_name() {
            if let Some(name) = driver_name.to_str() {
                return Ok(name.to_string());
            }
        }
    }

    // fallback for virtual interfaces
    let uevent_path = format!("/sys/class/net/{}/uevent", interface);
    if let Ok(content) = fs::read_to_string(&uevent_path) {
        for line in content.lines() {
            if line.starts_with("DEVTYPE=") {
                return Ok(line.replace("DEVTYPE=", ""));
            }
        }
    }

    Ok("unknown".to_string())
}

fn check_xdp_support(interface: &str) -> Result<CheckResult> {
    let xdp_path = format!("/sys/class/net/{}/xdp", interface);
    let xdp_prog_path = format!("{}/prog_id", xdp_path);

    if !Path::new(&xdp_path).exists() {
        // nothing found
        // check if the driver is in the known good list
        let driver = interface_driver(interface).unwrap_or_else(|_| "unknown".to_string());
        if GOOD_DRIVERS.contains(&driver.as_str()) {
            return Ok(CheckResult {
                name: format!("{}: XDP Support", interface),
                status: CheckStatus::Pass,
                message: "XDP-capable (driver supports native XDP)".to_string(),
                details: Some(format!("Driver {} supports XDP but sysfs entries not visible", driver)),
            });
        }

        return Ok(CheckResult {
            name: format!("{}: XDP Support", interface),
            status: CheckStatus::Warning,
            message: "No XDP support detected".to_string(),
            details: Some("XDP sysfs entries not found. Driver may not support native XDP.".to_string()),
        });
    }

    // is XDP program is attached
    if let Ok(prog_id) = fs::read_to_string(&xdp_prog_path) {
        let prog_id = prog_id.trim();
        if prog_id != "0" && !prog_id.is_empty() {
            return Ok(CheckResult {
                name: format!("{}: XDP Support", interface),
                status: CheckStatus::Pass,
                message: format!("XDP program attached (ID: {})", prog_id),
                details: Some("Interface has an active XDP program".to_string()),
            });
        }
    }

    Ok(CheckResult {
        name: format!("{}: XDP Support", interface),
        status: CheckStatus::Pass,
        message: "XDP-ready (no program attached)".to_string(),
        details: Some("Interface supports XDP but no program is currently attached".to_string()),
    })
}

/// get number of RX and TX queues
fn interface_queues(interface: &str) -> Result<(usize, usize)> {
    let queue_path = format!("/sys/class/net/{}/queues", interface);

    let mut rx_queues = 0;
    let mut tx_queues = 0;

    if let Ok(entries) = fs::read_dir(&queue_path) {
        for entry in entries {
            if let Ok(entry) = entry {
                if let Some(name) = entry.file_name().to_str() {
                    if name.starts_with("rx-") {
                        rx_queues += 1;
                    } else if name.starts_with("tx-") {
                        tx_queues += 1;
                    }
                }
            }
        }
    }

    // if no queues found in sysfs, assume at least 1. need to check
    if rx_queues == 0 {
        rx_queues = 1;
    }
    if tx_queues == 0 {
        tx_queues = 1;
    }

    Ok((rx_queues, tx_queues))
}

/// ring buffer parameters using ethtool ioctl (alessandros device check)
fn ring_parameters_ethtool(interface: &str) -> Result<(u32, u32)> {
    // create socket for ioctl
    let fd = unsafe { socket(AF_INET, SOCK_DGRAM, 0) };
    if fd < 0 {
        return Err(anyhow::anyhow!("Failed to create socket"));
    }
    let fd = unsafe { OwnedFd::from_raw_fd(fd) };

    let mut ring_param: EthtoolRingParam = unsafe { mem::zeroed() };
    ring_param.cmd = ETHTOOL_GRINGPARAM;

    let mut ifr: ifreq = unsafe { mem::zeroed() };
    let if_name_bytes = interface.as_bytes();
    let len = if_name_bytes.len().min(IF_NAMESIZE - 1);
    unsafe {
        ptr::copy_nonoverlapping(
            if_name_bytes.as_ptr() as *const i8,
            ifr.ifr_name.as_mut_ptr(),
            len,
        );
    }
    ifr.ifr_name[IF_NAMESIZE - 1] = 0;
    ifr.ifr_ifru.ifru_data = &mut ring_param as *mut _ as *mut i8;

    let res = unsafe { ioctl(fd.as_raw_fd(), SIOCETHTOOL, &ifr) };
    if res < 0 {
        return Err(anyhow::anyhow!("ethtool ioctl failed"));
    }

    Ok((ring_param.rx_pending, ring_param.tx_pending))
}