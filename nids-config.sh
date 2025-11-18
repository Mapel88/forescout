#!/bin/bash

# ==============================================================================
# NIDS Network Configuration Script (nids-config.sh)
#
# Description:
# Configures essential network settings for a NIDS. Accepts command-line arguments
# or prompts user for IPv6 privacy extensions and IPv4 forwarding settings.
# ==============================================================================

SCRIPT_NAME="NIDS Network Configurator"
CONFIG_FILE="/etc/sysctl.d/99-nids-network.conf"
IPV6_MODE="" # Target value for net.ipv6.conf.*.use_tempaddr (0, 1, or 2)
IPV4_FORWARD="" # Target value for net.ipv4.ip_forward (0 or 1)

# --- Function to display usage information ---
show_usage() {
    echo "Usage: sudo $0 [IPV6_MODE] [IPV4_FORWARD]"
    echo ""
    echo "Arguments:"
    echo "  IPV6_MODE:   0 (Disable), 1 (Enable), or 2 (Prefer privacy addresses, default)"
    echo "  IPV4_FORWARD: 0 (Disable) or 1 (Enable, required for gateway/routing, default)"
    echo ""
    echo "Example (Interactive): sudo $0"
    echo "Example (Automated): sudo $0 2 1"
    exit 1
}

# --- Function to check if arguments are valid ---
validate_input() {
    local value=$1
    local valid_values=$2
    local setting_name=$3
    
    if [[ ! " $valid_values " =~ " $value " ]]; then
        echo "ERROR: Invalid value for $setting_name: '$value'."
        show_usage
    fi
}

# --- Function to apply changes using sysctl ---
apply_sysctl_changes() {
    echo "-> Applying new sysctl settings..."
    cat "$CONFIG_FILE"
    if sysctl -p "$CONFIG_FILE" &>/dev/null; then
        echo "   [SUCCESS] New settings loaded successfully."
    else
        echo "   [ERROR] Failed to load new sysctl settings. Check $CONFIG_FILE for errors."
        exit 1
    fi
}

# --- Function to prompt for IPv6 Mode input ---
prompt_ipv6_mode() {
    echo ""
    echo "========================================================"
    echo ">> IPv6 Privacy Extensions Configuration <<"
    echo "========================================================"
    echo "Select desired IPv6 Privacy Mode (net.ipv6.conf.*.use_tempaddr):"
    echo "  0) Disable privacy extensions (Default/EUI-64)"
    echo "  1) Enable privacy extensions (Temporary addresses used)"
    echo "  2) Prefer privacy addresses (Recommended for NIDS environments)"
    
    while true; do
        read -p "Enter 0, 1, or 2 [Default: 2]: " INPUT
        # Use default if input is empty
        IPV6_MODE=${INPUT:-2}

        if [[ "$IPV6_MODE" =~ ^[0-2]$ ]]; then
            break
        else
            echo "Invalid input. Please enter 0, 1, or 2."
        fi
    done
}

# --- Function to prompt for IPv4 Forwarding input ---
prompt_ipv4_forwarding() {
    echo ""
    echo "========================================================"
    echo ">> IPv4 Forwarding Configuration <<"
    echo "========================================================"
    echo "Do you want to ENABLE IPv4 Forwarding? (net.ipv4.ip_forward)"
    echo "  (Required if the NIDS system acts as a gateway/router.)"
    
    while true; do
        read -p "Enable (Y/n) [Default: Y]: " INPUT
        # Default to Y if input is empty
        CHOICE=${INPUT:-Y}
        
        if [[ "$CHOICE" =~ ^[Yy]$ ]]; then
            IPV4_FORWARD=1
            break
        elif [[ "$CHOICE" =~ ^[Nn]$ ]]; then
            IPV4_FORWARD=0
            break
        else
            echo "Invalid input. Please enter Y or n."
        fi
    done
}

# --- Function to apply the configuration to the file ---
write_configuration() {
    echo ""
    echo "-> Writing configuration to $CONFIG_FILE"

    # 1. Write IPv6 Configuration
    echo "### IPv6 Configuration for NIDS ###" | tee -a "$CONFIG_FILE" > /dev/null
    echo "net.ipv6.conf.all.use_tempaddr = $IPV6_MODE" | tee -a "$CONFIG_FILE" > /dev/null
    echo "net.ipv6.conf.default.use_tempaddr = $IPV6_MODE" | tee -a "$CONFIG_FILE" > /dev/null
    
    # addr_gen_mode 2 (Stable Privacy) is often set alongside use_tempaddr 2
    if [ "$IPV6_MODE" -eq 2 ]; then
        echo "net.ipv6.conf.all.addr_gen_mode = 2" | tee -a "$CONFIG_FILE" > /dev/null
        echo "net.ipv6.conf.default.addr_gen_mode = 2" | tee -a "$CONFIG_FILE" > /dev/null
    fi

    # 2. Write IPv4 Configuration
    echo "" | tee -a "$CONFIG_FILE" > /dev/null
    echo "### IPv4 Configuration for NIDS ###" | tee -a "$CONFIG_FILE" > /dev/null
    echo "net.ipv4.ip_forward = $IPV4_FORWARD" | tee -a "$CONFIG_FILE" > /dev/null
}


# --- Main Execution ---

# Check for root permissions immediately
if [[ $EUID -ne 0 ]]; then
   echo "This script must be run with 'sudo' or as root." 
   exit 1
fi

echo "========================================================"
echo "Starting $SCRIPT_NAME for NIDS Environment..."
echo "========================================================"

# --- 1. Process Arguments or Request Input ---

if [ $# -gt 0 ]; then
    # Arguments received (Automated Mode)
    
    # 1. Check for IPv6 Mode argument
    IPV6_MODE=$1
    validate_input "$IPV6_MODE" "0 1 2" "IPV6_MODE"

    # 2. Check for IPv4 Forwarding argument
    IPV4_FORWARD=${2:-1} # Default to 1 (Enable) if second argument is missing
    validate_input "$IPV4_FORWARD" "0 1" "IPV4_FORWARD"

    echo "Mode: Automated"
    echo "Using settings: IPv6 Mode=$IPV6_MODE, IPv4 Forward=$IPV4_FORWARD"

else
    # No arguments received (Interactive Mode)
    echo "Mode: Interactive"
    prompt_ipv6_mode
    prompt_ipv4_forwarding
fi

# --- 2. Configuration Steps ---

# 3. Prepare Configuration File (Backup existing, create new)
if [ -f "$CONFIG_FILE" ]; then
    echo ""
    echo "-> Backup existing NIDS config file before making changes..."
    mv "$CONFIG_FILE" "$CONFIG_FILE.bak.$(date +%Y%m%d%H%M%S)"
fi
echo "-> Creating new configuration file: $CONFIG_FILE"
touch "$CONFIG_FILE"

# 4. Write Configuration and Apply changes
# Note: Since the script is running as root (checked at the top), we don't need 'sudo' 
# inside the script for file operations anymore, simplifying the writing process.
write_configuration
apply_sysctl_changes

# 5. Verification
echo ""
echo "========================================================"
echo ">> Final Verification <<"
echo "========================================================"
echo "net.ipv4.ip_forward is now: $(sysctl -n net.ipv4.ip_forward)"
echo "net.ipv6.conf.all.use_tempaddr is now: $(sysctl -n net.ipv6.conf.all.use_tempaddr)"
echo "Configuration complete. Settings are active and persistent."

exit 0