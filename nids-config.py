#!/usr/bin/env python3
"""
NIDS Configuration Tool
Configures IPv4/IPv6 protocol monitoring and network interfaces for NIDS
"""

import os
import sys
import yaml
import argparse
import subprocess
from datetime import datetime
from pathlib import Path

# Configuration paths
CONFIG_FILE = '/etc/nids/config.yaml'
CONFIG_DIR = '/etc/nids'

# Default configuration
DEFAULT_CONFIG = {
    'ipv4_enabled': True,
    'ipv6_enabled': True,
    'interfaces': [],
    'last_updated': None
}


class NIDSConfig:
    """NIDS Configuration Manager"""
    
    def __init__(self, config_file=CONFIG_FILE):
        self.config_file = config_file
        self.config = self.load_config()
    
    def load_config(self):
        """Load configuration from file or create default"""
        try:
            if os.path.exists(self.config_file):
                with open(self.config_file, 'r') as f:
                    config = yaml.safe_load(f)
                    # Merge with defaults in case of missing keys
                    return {**DEFAULT_CONFIG, **(config or {})}
            else:
                return DEFAULT_CONFIG.copy()
        except Exception as e:
            print(f"Error loading config: {e}", file=sys.stderr)
            return DEFAULT_CONFIG.copy()
    
    def save_config(self):
        """Save configuration to file"""
        try:
            # Ensure config directory exists
            os.makedirs(CONFIG_DIR, exist_ok=True)
            
            # Update timestamp
            self.config['last_updated'] = datetime.now().isoformat()
            
            with open(self.config_file, 'w') as f:
                yaml.dump(self.config, f, default_flow_style=False)
            return True
        except Exception as e:
            print(f"Error saving config: {e}", file=sys.stderr)
            return False

    def _apply_kernel_ipv6(self, enable: bool) -> bool:
        """Apply kernel-level IPv6 enable/disable using sysctl.
        Requires root. Returns True on success."""
        if os.geteuid() != 0: # type: ignore
            print("Error: kernel IPv6 changes require root privileges.", file=sys.stderr)
            return False

        val = '0' if enable else '1'
        cmds = [
            ['sysctl', '-w', f'net.ipv6.conf.all.disable_ipv6={val}'],
            ['sysctl', '-w', f'net.ipv6.conf.default.disable_ipv6={val}']
        ]

        for cmd in cmds:
            try:
                result = subprocess.run(cmd, capture_output=True, text=True, check=True)
            except subprocess.CalledProcessError as e:
                out = e.stdout.strip() if e.stdout else ''
                err = e.stderr.strip() if e.stderr else ''
                print(f"Error applying sysctl {' '.join(cmd)}: {err or out}", file=sys.stderr)
                return False
            except FileNotFoundError:
                print("Error: 'sysctl' command not found. Cannot change kernel IPv6 settings.", file=sys.stderr)
                return False

        return True
    
    def enable_ipv6(self):
        """Enable IPv6 monitoring and attempt to enable IPv6 in the kernel"""
        # Try to apply kernel change first (safer to fail early)
        if not self._apply_kernel_ipv6(True):
            print("Failed to enable IPv6 at kernel level. Aborting change.", file=sys.stderr)
            return False

        self.config['ipv6_enabled'] = True
        if self.save_config():
            print("✓ IPv6 monitoring enabled (and kernel IPv6 enabled)")
            return True
        return False
    
    def disable_ipv6(self):
        """Disable IPv6 monitoring and attempt to disable IPv6 in the kernel"""
        if not self._apply_kernel_ipv6(False):
            print("Failed to disable IPv6 at kernel level. Aborting change.", file=sys.stderr)
            return False

        self.config['ipv6_enabled'] = False
        if self.save_config():
            print("✓ IPv6 monitoring disabled (and kernel IPv6 disabled)")
            return True
        return False
    
    def enable_ipv4(self):
        """Enable IPv4 monitoring (updates config only). Kernel-level toggling for IPv4 is not supported."""
        print("Note: IPv4 kernel-level enable/disable is not supported by this tool. Updating config only.")
        self.config['ipv4_enabled'] = True
        if self.save_config():
            print("✓ IPv4 monitoring enabled (config updated)")
            return True
        return False
    
    def disable_ipv4(self):
        """Disable IPv4 monitoring (updates config only). Kernel-level toggling for IPv4 is not supported."""
        print("Note: IPv4 kernel-level enable/disable is not supported by this tool. Updating config only.")
        self.config['ipv4_enabled'] = False
        if self.save_config():
            print("✓ IPv4 monitoring disabled (config updated)")
            return True
        return False
    
    def get_status(self):
        """Get current configuration status"""
        return {
            'ipv4': 'ENABLED' if self.config.get('ipv4_enabled', True) else 'DISABLED',
            'ipv6': 'ENABLED' if self.config.get('ipv6_enabled', True) else 'DISABLED',
            'interfaces': self.config.get('interfaces', []),
            'last_updated': self.config.get('last_updated', 'Never')
        }


class NetworkInterface:
    """Network Interface Manager"""
    
    @staticmethod
    def get_active_interfaces():
        """Dynamically discover active network interfaces"""
        interfaces = []
        sys_net = '/sys/class/net'
        
        if not os.path.exists(sys_net):
            print(f"Warning: {sys_net} not found. Cannot detect interfaces.", file=sys.stderr)
            return interfaces
        
        for iface in os.listdir(sys_net):
            # Skip loopback
            if iface == 'lo':
                continue
            
            # Check if interface is up
            operstate_path = os.path.join(sys_net, iface, 'operstate')
            if os.path.exists(operstate_path):
                try:
                    with open(operstate_path, 'r') as f:
                        state = f.read().strip()
                        if state == 'up':
                            interfaces.append(iface)
                except Exception as e:
                    print(f"Warning: Could not read state for {iface}: {e}", file=sys.stderr)
        
        return interfaces
    
    @staticmethod
    def check_ipv6_support():
        """Check if IPv6 is enabled in the kernel"""
        try:
            result = subprocess.run(
                ['sysctl', 'net.ipv6.conf.all.disable_ipv6'],
                capture_output=True,
                text=True,
                check=False
            )
            if result.returncode == 0:
                # Output format: net.ipv6.conf.all.disable_ipv6 = 0
                value = result.stdout.strip().split('=')[-1].strip()
                return value == '0'
            return False
        except Exception:
            return False
    
    @staticmethod
    def enable_promiscuous_mode(interface):
        """Enable promiscuous mode on interface"""
        try:
            subprocess.run(
                ['ip', 'link', 'set', interface, 'promisc', 'on'],
                check=True,
                capture_output=True
            )
            return True
        except subprocess.CalledProcessError as e:
            print(f"Error enabling promiscuous mode on {interface}: {e}", file=sys.stderr)
            return False
        except FileNotFoundError:
            print("Error: 'ip' command not found. Please install iproute2.", file=sys.stderr)
            return False
    
    @staticmethod
    def check_promiscuous_mode(interface):
        """Check if interface is in promiscuous mode"""
        flags_path = f'/sys/class/net/{interface}/flags'
        try:
            with open(flags_path, 'r') as f:
                flags = int(f.read().strip(), 16)
                # IFF_PROMISC = 0x100
                return bool(flags & 0x100)
        except Exception:
            return False


def check_permissions():
    """Check if running with sufficient permissions"""
    if os.geteuid() != 0: # type: ignore
        print("Error: This script requires root privileges.", file=sys.stderr)
        print("Please run with sudo or as root.", file=sys.stderr)
        return False
    return True


def print_status(nids_config):
    """Print current NIDS configuration status"""
    status = nids_config.get_status()
    interfaces = NetworkInterface.get_active_interfaces()
    ipv6_kernel = NetworkInterface.check_ipv6_support()
    
    print("\n" + "=" * 50)
    print("NIDS Configuration Status")
    print("=" * 50)
    
    print(f"\nProtocol Monitoring:")
    print(f"  IPv4: {status['ipv4']}")
    print(f"  IPv6: {status['ipv6']}")
    
    print(f"\nKernel IPv6 Support: {'ENABLED' if ipv6_kernel else 'DISABLED'}")
    
    print(f"\nActive Network Interfaces: {', '.join(interfaces) if interfaces else 'None'}")
    print(f"Configured Interfaces: {', '.join(status['interfaces']) if status['interfaces'] else 'None'}")
    
    if status['interfaces']:
        print(f"\nInterface Status:")
        for iface in status['interfaces']:
            promisc = NetworkInterface.check_promiscuous_mode(iface)
            status_icon = "✓" if promisc else "✗"
            status_text = "Ready" if promisc else "Not in promiscuous mode"
            print(f"  {status_icon} {iface}: {status_text}")
    
    print(f"\nLast Updated: {status['last_updated']}")
    print("=" * 50 + "\n")


def configure_all_interfaces(nids_config):
    """Auto-configure all active interfaces"""
    if not check_permissions():
        return False
    
    interfaces = NetworkInterface.get_active_interfaces()
    
    if not interfaces:
        print("Warning: No active network interfaces found.", file=sys.stderr)
        return False
    
    print(f"Found {len(interfaces)} active interface(s): {', '.join(interfaces)}")
    
    success_count = 0
    for iface in interfaces:
        print(f"\nConfiguring {iface}...", end=" ")
        if NetworkInterface.enable_promiscuous_mode(iface):
            print("✓ Promiscuous mode enabled")
            success_count += 1
        else:
            print("✗ Failed")
    
    # Update config with all interfaces
    nids_config.config['interfaces'] = interfaces
    nids_config.save_config()
    
    print(f"\n✓ Successfully configured {success_count}/{len(interfaces)} interface(s) for NIDS")
    return success_count > 0


def validate_environment():
    """Validate system environment for NIDS"""
    print("\n" + "=" * 50)
    print("NIDS Environment Validation")
    print("=" * 50 + "\n")
    
    checks = []
    
    # Check 1: Root privileges
    has_root = os.geteuid() == 0 # type: ignore
    checks.append(("Root privileges", has_root))
    
    # Check 2: IPv6 kernel support
    ipv6_enabled = NetworkInterface.check_ipv6_support()
    checks.append(("IPv6 kernel support", ipv6_enabled))
    
    # Check 3: Active interfaces
    interfaces = NetworkInterface.get_active_interfaces()
    has_interfaces = len(interfaces) > 0
    checks.append((f"Active interfaces ({len(interfaces)} found)", has_interfaces))
    
    # Check 4: Config file
    config_exists = os.path.exists(CONFIG_FILE)
    checks.append(("Configuration file", config_exists))
    
    # Check 5: ip command available
    try:
        subprocess.run(['ip', '--version'], capture_output=True, check=True)
        has_ip = True
    except:
        has_ip = False
    checks.append(("'ip' command available", has_ip))
    
    # Print results
    all_passed = True
    for check_name, passed in checks:
        status = "✓ PASS" if passed else "✗ FAIL"
        print(f"{status} - {check_name}")
        if not passed:
            all_passed = False
    
    print("\n" + "=" * 50)
    if all_passed:
        print("✓ All checks passed. System is ready for NIDS.")
    else:
        print("✗ Some checks failed. Please resolve issues above.")
    print("=" * 50 + "\n")
    
    return all_passed


def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(
        description='NIDS Configuration Tool - Configure IPv4/IPv6 monitoring',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s --enable-ipv6              Enable IPv6 monitoring (and kernel IPv6)
  %(prog)s --disable-ipv6             Disable IPv6 monitoring (and kernel IPv6)
  %(prog)s --configure-all            Auto-configure all interfaces
  %(prog)s --status                   Show current configuration
  %(prog)s --validate                 Validate system environment
        """
    )
    
    # Protocol options
    parser.add_argument('--enable-ipv6', action='store_true',
                       help='Enable IPv6 monitoring')
    parser.add_argument('--disable-ipv6', action='store_true',
                       help='Disable IPv6 monitoring')
    parser.add_argument('--enable-ipv4', action='store_true',
                       help='Enable IPv4 monitoring')
    parser.add_argument('--disable-ipv4', action='store_true',
                       help='Disable IPv4 monitoring')
    
    # Interface options
    parser.add_argument('--configure-all', action='store_true',
                       help='Auto-configure all active network interfaces')
    
    # Status and validation
    parser.add_argument('--status', action='store_true',
                       help='Show current NIDS configuration status')
    parser.add_argument('--validate', action='store_true',
                       help='Validate system environment for NIDS')
    
    # Config file override
    parser.add_argument('--config', default=CONFIG_FILE,
                       help=f'Configuration file path (default: {CONFIG_FILE})')
    
    args = parser.parse_args()
    
    # If no arguments, show help
    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(0)
    
    # Initialize configuration manager
    nids_config = NIDSConfig(args.config)
    
    # Handle commands
    success = True
    
    if args.validate:
        success = validate_environment()
    
    if args.enable_ipv6:
        success = nids_config.enable_ipv6() and success
    
    if args.disable_ipv6:
        success = nids_config.disable_ipv6() and success
    
    if args.enable_ipv4:
        success = nids_config.enable_ipv4() and success
    
    if args.disable_ipv4:
        success = nids_config.disable_ipv4() and success
    
    if args.configure_all:
        success = configure_all_interfaces(nids_config) and success
    
    if args.status:
        print_status(nids_config)
    
    sys.exit(0 if success else 1)


if __name__ == '__main__':
    main()