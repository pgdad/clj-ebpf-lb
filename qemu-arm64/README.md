# QEMU ARM64 Testing for clj-ebpf-reverse-proxy

This directory contains tools for running clj-ebpf-reverse-proxy tests on an ARM64 Linux virtual machine using QEMU system emulation.

## Overview

This uses a full QEMU system VM which provides:
- **Real ARM64 Linux kernel** - BPF syscalls execute on ARM64 kernel
- **Full BPF support** - All privileged BPF operations work
- **Accurate testing** - True cross-architecture verification

## Quick Start

### 1. Setup (One-time)

```bash
# Install QEMU and download Ubuntu ARM64 image
./qemu-arm64/setup-vm.sh
```

This will:
- Install `qemu-system-aarch64` and dependencies
- Download Ubuntu 24.04 ARM64 cloud image (~600MB)
- Create a 20GB VM disk
- Generate cloud-init configuration

### 2. Start the VM

```bash
# Interactive mode (see console output)
./qemu-arm64/start-vm.sh

# Or daemon mode (background)
./qemu-arm64/start-vm.sh --daemon
```

First boot takes 2-3 minutes for cloud-init to:
- Install Java 25
- Install Clojure CLI
- Configure SSH access

### 3. Sync and Run Tests

```bash
# Sync project files and run tests
./qemu-arm64/run-tests-in-vm.sh --sync

# Or just run tests (if already synced)
./qemu-arm64/run-tests-in-vm.sh
```

### 4. Stop the VM

```bash
./qemu-arm64/stop-vm.sh
```

## Scripts

| Script | Description |
|--------|-------------|
| `setup-vm.sh` | One-time setup: install QEMU, download image, create disk |
| `start-vm.sh` | Launch the ARM64 VM (interactive or daemon mode) |
| `stop-vm.sh` | Stop the running VM |
| `sync-project.sh` | Copy project files to the VM via rsync |
| `run-tests-in-vm.sh` | Execute tests inside the VM via SSH |

## Manual Access

SSH into the VM:
```bash
ssh -p 2222 ubuntu@localhost
```

Run tests manually:
```bash
cd /home/ubuntu/clj-ebpf-reverse-proxy
sudo clojure -M:test
```

## VM Specifications

| Resource | Value |
|----------|-------|
| Architecture | ARM64 (aarch64) |
| CPU | Cortex-A72 (emulated) |
| CPUs | 4 |
| Memory | 4GB |
| Disk | 20GB |
| OS | Ubuntu 24.04 Noble |
| Kernel | 6.8+ |
| Java | OpenJDK 25 |
| SSH Port | 2222 |

## Cloud-Init Configuration

The VM is provisioned with `cloud-init/user-data`:
- User: `ubuntu` (passwordless sudo)
- SSH key configured for access
- Packages: Java 25, Clojure, git, bpftool

## Directory Structure

```
qemu-arm64/
├── README.md                 # This file
├── setup-vm.sh              # One-time setup script
├── start-vm.sh              # Launch VM
├── stop-vm.sh               # Stop VM
├── sync-project.sh          # Sync files to VM
├── run-tests-in-vm.sh       # Run tests in VM
├── cloud-init/
│   ├── user-data            # Cloud-init configuration
│   └── meta-data            # Instance metadata
├── noble-server-cloudimg-arm64.img  # Base image (downloaded)
├── vm-disk.qcow2            # VM disk (created)
├── seed.img                 # Cloud-init seed (created)
├── vm.pid                   # PID file (when running)
└── vm.log                   # Console log (daemon mode)
```

## Performance

QEMU system emulation is slower than native:

| Environment | Test Time | Notes |
|-------------|-----------|-------|
| Native x86_64 | ~15s | Baseline |
| Native ARM64 | ~16s | ~6% slower |
| QEMU ARM64 | ~3-5min | 10-20x slower (emulation) |

For faster ARM64 testing, consider:
- Native ARM64 hardware (AWS Graviton, Oracle A1)
- Apple Silicon Macs (native ARM64)
- Raspberry Pi 4/5 (slower but native)

## Troubleshooting

### VM won't start

```bash
# Check UEFI firmware is installed
ls /usr/share/qemu-efi-aarch64/QEMU_EFI.fd

# If missing, install it
sudo apt-get install qemu-efi-aarch64
```

### Can't SSH to VM

```bash
# Check if VM is running
ps aux | grep qemu-system-aarch64

# Check if port 2222 is listening
ss -tlnp | grep 2222

# View VM console log
tail -f qemu-arm64/vm.log
```

### Cloud-init not completing

First boot takes 2-3 minutes. Check progress:
```bash
ssh -p 2222 ubuntu@localhost
sudo cloud-init status --wait
cat /var/log/cloud-init-output.log
```

### BPF tests failing

Ensure the VM kernel supports BPF:
```bash
ssh -p 2222 ubuntu@localhost
zgrep CONFIG_BPF /proc/config.gz
sudo bpftool prog list
```

### Out of disk space

The VM disk is 20GB. Check usage:
```bash
ssh -p 2222 ubuntu@localhost
df -h /
```
