#!/usr/bin/env python3
import argparse
import os
import shlex
import subprocess
import sys
from typing import List, Optional

# Try to import PyYAML, fallback to tiny parser
try:
    import yaml  # type: ignore
except Exception:
    yaml = None  # type: ignore

DEFAULT_CONFIG = "/etc/nids/config.yaml"


def run(cmd: List[str], capture: bool = True) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, capture_output=capture, text=True)


def load_yaml_simple(path: str) -> dict:
    data = {"ipv4_enabled": None, "ipv6_enabled": None, "interfaces": []}
    if not os.path.exists(path):
        return data
    with open(path, "r") as f:
        key = None
        for line in f:
            s = line.strip()
            if not s or s.startswith("#"):
                continue
            if ":" in s and not s.startswith("-"):
                k, v = [p.strip() for p in s.split(":", 1)]
                if k == "interfaces":
                    key = "interfaces"
                    continue
                if v.lower() in ("true", "false"):
                    data[k] = v.lower() == "true"
                else:
                    data[k] = v or None
            elif s.startswith("-") and key == "interfaces":
                item = s.lstrip("-").strip()
                if item:
                    data["interfaces"].append(item)
            else:
                key = None
    return data


def load_config(path: str) -> dict:
    if yaml:
        try:
            with open(path, "r") as f:
                parsed = yaml.safe_load(f) or {}
            # Normalize
            return {
                "ipv4_enabled": parsed.get("ipv4_enabled"),
                "ipv6_enabled": parsed.get("ipv6_enabled"),
                "interfaces": parsed.get("interfaces") or [],
            }
        except Exception:
            return load_yaml_simple(path)
    else:
        return load_yaml_simple(path)


def check_sysctl_ipv6_enabled() -> Optional[bool]:
    try:
        p = run(["sysctl", "net.ipv6.conf.all.disable_ipv6"])
        if p.returncode != 0:
            return None
        # expect "net.ipv6.conf.all.disable_ipv6 = 0"
        out = p.stdout.strip()
        if "=" in out:
            val = out.split("=", 1)[1].strip()
            return val == "0"
        return None
    except FileNotFoundError:
        return None


def interface_in_promisc(iface: str) -> Optional[bool]:
    # Prefer `ip` output
    ip_bin = shutil_which("ip")
    if ip_bin:
        try:
            p = run([ip_bin, "-o", "link", "show", iface])
            if p.returncode != 0:
                return None
            return "PROMISC" in p.stdout
        except Exception:
            return None
    # Fallback: read /sys/class/net/<iface>/flags (hex)
    flags_path = f"/sys/class/net/{iface}/flags"
    if os.path.exists(flags_path):
        try:
            with open(flags_path, "r") as f:
                raw = f.read().strip()
            # some systems show 0x...; int() handles both
            flags = int(raw, 0)
            return bool(flags & 0x100)  # IFF_PROMISC
        except Exception:
            return None
    return None


def shutil_which(name: str) -> Optional[str]:
    # avoid importing shutil at top to keep small
    for p in os.environ.get("PATH", "").split(os.pathsep):
        p = p.strip('"')
        exe = os.path.join(p, name)
        if os.path.isfile(exe) and os.access(exe, os.X_OK):
            return exe
    return None


def run_configure_all(sudo: str) -> bool:
    cmd = [sudo, "nids-config", "--configure-all"] if sudo else ["nids-config", "--configure-all"]
    try:
        p = run([c for c in cmd if c], capture=True)
        return p.returncode == 0
    except FileNotFoundError:
        return False


def parse_args():
    ap = argparse.ArgumentParser(description="Validate nids-config installation and runtime settings")
    ap.add_argument("--config", default=DEFAULT_CONFIG)
    ap.add_argument("--expect-ipv6", choices=["true", "false", "skip"], default="skip")
    ap.add_argument("--expect-ipv4", choices=["true", "false", "skip"], default="skip")
    ap.add_argument("--run-configure-all", action="store_true")
    return ap.parse_args()


def main():
    args = parse_args()
    sudo = "sudo" if os.geteuid() != 0 and shutil_which("sudo") else "" # type: ignore
    failures = 0

    if not os.path.exists(args.config):
        print(f"ERROR: config not found: {args.config}", file=sys.stderr)
        failures += 1
    else:
        print(f"Using config: {args.config}")

    cfg = load_config(args.config)

    def check_expected(key: str, expected: str):
        nonlocal failures
        val = cfg.get(key)
        if val is None:
            print(f"ERROR: {key} missing in config", file=sys.stderr)
            failures += 1
            return
        actual = "true" if bool(val) else "false"
        if expected != "skip" and actual != expected:
            print(f"ERROR: {key} mismatch expected={expected} actual={actual}", file=sys.stderr)
            failures += 1
        else:
            if expected != "skip":
                print(f"{key} matches expected: {actual}")

    if args.expect_ipv6 != "skip":
        check_expected("ipv6_enabled", args.expect_ipv6)
        if args.expect_ipv6 == "true":
            ipv6_kernel = check_sysctl_ipv6_enabled()
            if ipv6_kernel is True:
                print("Kernel IPv6 enabled (disable_ipv6=0)")
            elif ipv6_kernel is False:
                print("ERROR: Kernel IPv6 is NOT enabled", file=sys.stderr)
                failures += 1
            else:
                print("ERROR: Cannot determine kernel IPv6 state (sysctl missing?)", file=sys.stderr)
                failures += 1

    if args.expect_ipv4 != "skip":
        check_expected("ipv4_enabled", args.expect_ipv4)

    if args.run_configure_all:
        print("Running configure-all (may need root)...")
        ok = run_configure_all(sudo)
        if not ok:
            print("Warning: configure-all failed or unavailable (container/permissions?)", file=sys.stderr)

    interfaces: List[str] = cfg.get("interfaces") or []
    if not interfaces:
        print("No configured interfaces in config")
    else:
        print("Configured interfaces:")
        for i in interfaces:
            print(f"  - {i}")

        ip_bin = shutil_which("ip")
        if not ip_bin:
            print("ERROR: 'ip' command not available to check promiscuous mode", file=sys.stderr)
            failures += 1
        else:
            prom_ok = False
            for i in interfaces:
                if run([ip_bin, "link", "show", i]).returncode != 0:
                    print(f"ERROR: interface {i} not present", file=sys.stderr)
                    failures += 1
                    continue
                if "PROMISC" in run([ip_bin, "-o", "link", "show", i]).stdout:
                    print(f"Interface {i} is in promiscuous mode")
                    prom_ok = True
                else:
                    print(f"Interface {i} is NOT in promiscuous mode", file=sys.stderr)
            if not prom_ok:
                print("ERROR: No configured interface is in promiscuous mode", file=sys.stderr)
                failures += 1

    if failures == 0:
        print("All validations passed")
        return 0
    print(f"Validation completed with {failures} failure(s)", file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main())