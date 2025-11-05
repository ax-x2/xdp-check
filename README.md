# xdp-check

XDP compatibility checker and runtime verification

## overview

`xdp-check` verifies that your Linux system supports XDP and checks if XDP programs (specifically `agave_xdp`) are currently loaded and active.

## features

- **kernel compatibility check** - verifies kernel version and XDP support
- **capabilities check** - validates required system capabilities
- **system resources** - checks rlimit and memlock settings
- **network interface check** - verifies NIC driver support for XDP
- **runtime detection** - detects loaded XDP programs using BPF syscalls (via aya)

## requirements

- linux kernel 4.18+ (6.xx recommended for full XDP support)
- root/sudo privileges (for runtime checks and BPF operations)

## building

```bash
cargo build --release
```

the binary will be available at `./target/release/xdp-check`

## usage

### full sys
```bash
sudo ./xdp-check
```

### check runtime status
verify if `agave_xdp` or other XDP programs are currently loaded:
```bash
sudo ./xdp-check runtime
```

### check specific interface
```bash
sudo ./xdp-check nic eth0
```

### debug logging

enable detailed debug logs:
```bash
sudo RUST_LOG=debug ./xdp-check runtime
```

## runtime detection

runtime check uses the `aya` library to query loaded BPF programs directly via syscalls. it will detect:

- whether `agave_xdp` program is loaded
- program ID and tag/hash
- program type (XDP)
- other XDP programs in the system

## license

do what ever you want
