#!/usr/bin/env python3
"""
Kali setup bootstrap for scanner_wrapper.py requirements.

This script installs required system tools and Python dependencies, then verifies
tool availability. Run as root (or with sudo):

    sudo python3 setup.py
"""

from __future__ import annotations

import argparse
import os
import re
import shutil
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable


@dataclass(frozen=True)
class ToolRequirement:
    name: str
    binaries: tuple[str, ...]
    apt_candidates: tuple[str, ...]
    post_note: str = ""


REQUIREMENTS: tuple[ToolRequirement, ...] = (
    ToolRequirement("Nmap", ("nmap",), ("nmap",)),
    ToolRequirement("Nuclei", ("nuclei",), ("nuclei",)),
    ToolRequirement("Nikto", ("nikto",), ("nikto",)),
    ToolRequirement("Wapiti", ("wapiti",), ("wapiti",)),
    ToolRequirement("OWASP ZAP", ("zap.sh", "zaproxy", "owasp-zap"), ("zaproxy",)),
    ToolRequirement("SSLScan", ("sslscan",), ("sslscan",)),
    ToolRequirement("testssl.sh", ("testssl.sh", "testssl"), ("testssl.sh",)),
)


def run(cmd: list[str], check: bool = False) -> subprocess.CompletedProcess[str]:
    env = os.environ.copy()
    env.setdefault("DEBIAN_FRONTEND", "noninteractive")
    env.setdefault("APT_LISTCHANGES_FRONTEND", "none")
    env.setdefault("NEEDRESTART_MODE", "a")
    return subprocess.run(cmd, text=True, capture_output=True, check=check, env=env)


def run_stream(cmd: list[str], timeout: int = 7200) -> int:
    """
    Run a command with live output so long operations don't appear stuck.
    Returns process exit code.
    """
    env = os.environ.copy()
    env.setdefault("DEBIAN_FRONTEND", "noninteractive")
    env.setdefault("APT_LISTCHANGES_FRONTEND", "none")
    env.setdefault("NEEDRESTART_MODE", "a")

    print(f"[>] {' '.join(cmd)}")
    start = time.time()
    try:
        proc = subprocess.run(cmd, text=True, env=env, timeout=timeout, check=False)
    except subprocess.TimeoutExpired:
        print(f"[!] Command timed out after {timeout} seconds")
        return 124
    duration = int(time.time() - start)
    print(f"[<] Exit {proc.returncode} after {duration}s")
    return proc.returncode


def repair_interrupted_dpkg() -> bool:
    print("[+] Attempting recovery: dpkg --configure -a")
    rc = run_stream(["dpkg", "--configure", "-a"], timeout=1800)
    if rc == 0:
        print("[+] dpkg recovery completed")
        return True
    print(f"[!] dpkg recovery failed (exit {rc})")
    return False


def fix_broken_packages() -> bool:
    print("[+] Attempting recovery: apt --fix-broken install -y")
    rc = run_stream(
        ["apt-get", "-o", "DPkg::Lock::Timeout=120", "--fix-broken", "install", "-y"],
        timeout=5400,
    )
    if rc == 0:
        print("[+] Broken dependencies repaired")
        return True
    print(f"[!] apt --fix-broken install failed (exit {rc})")
    return False


def upgrade_minimal_system() -> bool:
    """
    Fallback for partial core-library transitions (common after interrupted upgrades).
    """
    print("[+] Attempting recovery: apt-get upgrade -y")
    rc = run_stream(
        ["apt-get", "-o", "DPkg::Lock::Timeout=120", "upgrade", "-y"],
        timeout=7200,
    )
    if rc == 0:
        print("[+] System upgrade completed")
        return True
    print(f"[!] apt-get upgrade failed (exit {rc})")
    return False


def apt_with_repair(cmd: list[str], timeout: int) -> int:
    """
    Run apt command with automated repair attempts and retry.
    """
    rc = run_stream(cmd, timeout=timeout)
    if rc == 0:
        return 0

    if not repair_interrupted_dpkg():
        return rc
    if not fix_broken_packages():
        return rc

    print("[+] Retrying apt command after dpkg/fix-broken recovery")
    rc = run_stream(cmd, timeout=timeout)
    if rc == 0:
        return 0

    # Last recovery step for mixed-version base system states.
    if upgrade_minimal_system():
        print("[+] Retrying apt command after upgrade recovery")
        return run_stream(cmd, timeout=timeout)
    return rc


def is_root() -> bool:
    return hasattr(os, "geteuid") and os.geteuid() == 0


def command_exists(binary: str) -> bool:
    return shutil.which(binary) is not None


def any_command_exists(binaries: Iterable[str]) -> bool:
    return any(command_exists(b) for b in binaries)


def disable_invalid_kali_docker_ubuntu_sources() -> int:
    """
    Disable known-bad Docker Ubuntu repo entries on Kali (kali-rolling).
    These entries cause apt-get update to fail with "does not have a Release file".
    """
    apt_dir = Path("/etc/apt/sources.list.d")
    if not apt_dir.is_dir():
        return 0

    disabled = 0
    entry_pattern = re.compile(
        r"^\s*deb(?:-src)?\s+\[[^\]]*\]\s+https?://download\.docker\.com/linux/ubuntu\s+kali-rolling\b|"
        r"^\s*deb(?:-src)?\s+https?://download\.docker\.com/linux/ubuntu\s+kali-rolling\b"
    )

    for path in sorted(apt_dir.glob("*.list")):
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        if not any(entry_pattern.search(line) for line in text.splitlines()):
            continue

        disabled_path = path.with_suffix(path.suffix + ".disabled")
        try:
            path.rename(disabled_path)
        except OSError as exc:
            print(f"[!] Failed to disable invalid apt source {path}: {exc}")
            continue
        disabled += 1
        print(f"[+] Disabled invalid Docker Ubuntu source on Kali: {path} -> {disabled_path}")
    return disabled


def apt_update() -> None:
    disable_invalid_kali_docker_ubuntu_sources()
    print("[+] Running apt-get update")
    rc = apt_with_repair(["apt-get", "-o", "DPkg::Lock::Timeout=120", "update"], timeout=1800)
    if rc != 0:
        print("[!] apt-get update failed")
        raise RuntimeError("apt-get update failed")


def apt_install_first_available(candidates: tuple[str, ...], label: str) -> bool:
    for pkg in candidates:
        print(f"[+] Trying apt package for {label}: {pkg}")
        rc = apt_with_repair(
            ["apt-get", "-o", "DPkg::Lock::Timeout=120", "install", "-y", pkg],
            timeout=5400,
        )
        if rc == 0:
            print(f"[+] Installed {label} via package: {pkg}")
            return True
        print(f"[-] Failed package {pkg} (exit {rc})")
    return False


def ensure_system_tools(skip_update: bool = False) -> None:
    if not skip_update:
        apt_update()

    for req in REQUIREMENTS:
        if any_command_exists(req.binaries):
            print(f"[+] {req.name} already installed")
            continue
        ok = apt_install_first_available(req.apt_candidates, req.name)
        if not ok:
            print(f"[!] Could not install {req.name} from apt candidates: {req.apt_candidates}")
            if req.post_note:
                print(f"    Note: {req.post_note}")


def ensure_zap_cli() -> None:
    if command_exists("zap-cli"):
        print("[+] zap-cli already installed")
        return

    if sys.version_info >= (3, 12):
        print("[!] Skipping zap-cli install on Python 3.12+ (legacy dependency stack is incompatible).")
        print("[!] scanner_wrapper.py uses native ZAP API and does not require zap-cli.")
        return

    print("[+] Installing zap-cli")
    # Kali often blocks global pip writes (PEP 668), so try pipx first.
    if not command_exists("pipx"):
        print("[+] Installing pipx")
        apt_with_repair(
            ["apt-get", "-o", "DPkg::Lock::Timeout=120", "install", "-y", "pipx"],
            timeout=3600,
        )

    if command_exists("pipx"):
        rc = run_stream(["pipx", "install", "zapcli"], timeout=1800)
        if rc == 0:
            print("[+] zap-cli installed via pipx")
            return
        print(f"[-] pipx install zapcli failed (exit {rc})")

    # Fallback to pip3 with --break-system-packages for Kali-managed Python.
    rc = run_stream(
        ["python3", "-m", "pip", "install", "--break-system-packages", "zapcli"],
        timeout=1800,
    )
    if rc == 0:
        print("[+] zap-cli installed via pip")
        return
    print(f"[!] Failed to install zap-cli (exit {rc})")


def ensure_python_basics() -> None:
    print("[+] Ensuring Python tooling")
    rc = apt_with_repair(
        ["apt-get", "-o", "DPkg::Lock::Timeout=120", "install", "-y", "python3-pip", "python3-venv"],
        timeout=3600,
    )
    if rc != 0:
        raise RuntimeError("Failed to install Python tooling")


def verify_installation() -> bool:
    expected_binaries: tuple[tuple[str, tuple[str, ...]], ...] = (
        ("Nmap", ("nmap",)),
        ("Nuclei", ("nuclei",)),
        ("Nikto", ("nikto",)),
        ("Wapiti", ("wapiti",)),
        ("OWASP ZAP", ("zap.sh", "zaproxy", "owasp-zap")),
        ("SSLScan", ("sslscan",)),
        ("testssl.sh", ("testssl.sh", "testssl")),
    )
    print("\n[+] Verifying installation")
    all_ok = True
    for name, binaries in expected_binaries:
        ok = any_command_exists(binaries)
        status = "OK" if ok else "MISSING"
        print(f"    - {name:12} ({'/'.join(binaries):20}): {status}")
        all_ok = all_ok and ok
    return all_ok


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Install Kali dependencies required by scanner_wrapper.py"
    )
    parser.add_argument(
        "--skip-update",
        action="store_true",
        help="Skip apt-get update (useful if already up-to-date)",
    )
    args = parser.parse_args()

    if not is_root():
        print("[!] Please run as root or with sudo.")
        sys.exit(1)

    ensure_python_basics()
    ensure_system_tools(skip_update=args.skip_update)
    ensure_zap_cli()

    ok = verify_installation()
    if not ok:
        print("\n[!] Setup finished with missing tools. Install remaining tools manually.")
        sys.exit(2)

    print("\n[+] Setup completed successfully.")
    print("[+] You can now run: python3 scanner_wrapper.py --targets-file targets.txt")


if __name__ == "__main__":
    main()
