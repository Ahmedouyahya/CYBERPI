#!/bin/bash

# Raspberry Pi Zero Cybersecurity Tool Setup Script
# This script automates the setup process for the educational cybersecurity tool

# Educational Purpose:
# - Demonstrates proper system configuration for security testing
# - Shows how to set up USB gadget functionality
# - Illustrates secure service configuration
# - Teaches automation and configuration management

set -euo pipefail

# Configuration variables
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
MOUNT_POINT="/mnt/usb_share"
USB_IMAGE="/piusb.bin"
USB_SIZE="2048"  # MB
USB_LABEL="TRUSTED_DRIVE"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging function
log() {
    local level="$1"
    shift
    local message="$*"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    
    case "$level" in
        "INFO")
            echo -e "${BLUE}[INFO]${NC} $timestamp: $message"
            ;;
        "WARN")
            echo -e "${YELLOW}[WARN]${NC} $timestamp: $message"
            ;;
        "ERROR")
            echo -e "${RED}[ERROR]${NC} $timestamp: $message"
            ;;
        "SUCCESS")
            echo -e "${GREEN}[SUCCESS]${NC} $timestamp: $message"
            ;;
    esac
}

# Check if running as root
check_root() {
    if [[ $EUID -ne 0 ]]; then
        log "ERROR" "This script must be run as root (use sudo)"
        exit 1
    fi
}

# Display educational disclaimer
show_disclaimer() {
    echo -e "${RED}"
    echo "================================================================="
    echo "        EDUCATIONAL CYBERSECURITY TOOL SETUP"
    echo "================================================================="
    echo
    echo "IMPORTANT DISCLAIMER:"
    echo "This tool is designed for educational purposes and authorized"
    echo "security testing only. Unauthorized use is illegal and unethical."
    echo
    echo "By proceeding with this setup, you acknowledge that:"
    echo "1. You will only use this tool on systems you own or have"
    echo "   explicit written permission to test"
    echo "2. You understand the legal implications of cybersecurity testing"
    echo "3. You will use this tool responsibly and ethically"
    echo "4. You will comply with all applicable laws and regulations"
    echo
    echo "================================================================="
    echo -e "${NC}"
    
    read -p "Do you accept these terms and wish to continue? (yes/no): " response
    if [[ "$response" != "yes" ]]; then
        log "INFO" "Setup cancelled by user"
        exit 0
    fi
}

# Update system packages
update_system() {
    log "INFO" "Updating system packages..."
    
    apt update
    apt full-upgrade -y
    
    log "SUCCESS" "System packages updated"
}

# Install required packages
install_dependencies() {
    log "INFO" "Installing required dependencies..."
    
    local packages=(
        "python3-pip"
        "libusb-1.0-0-dev"
        "git"
        "build-essential"
        "exfat-fuse"
        "exfat-utils"
        "dkms"
    )
    
    apt install -y "${packages[@]}"
    
    # Install Python packages from requirements.txt
    if [[ -f "$PROJECT_ROOT/requirements.txt" ]]; then
        log "INFO" "Installing Python packages from requirements.txt..."
        pip3 install -r "$PROJECT_ROOT/requirements.txt"
    else
        log "WARN" "requirements.txt not found, installing pycryptodomex only..."
        pip3 install pycryptodomex
    fi
    
    log "SUCCESS" "Dependencies installed"
}

# Configure USB gadget mode
configure_usb_gadget() {
    log "INFO" "Configuring USB gadget mode..."
    
    # Configure /boot/config.txt
    local config_txt="/boot/config.txt"
    local config_backup="/boot/config.txt.backup"
    
    # Create backup
    if [[ ! -f "$config_backup" ]]; then
        cp "$config_txt" "$config_backup"
        log "INFO" "Created backup of config.txt"
    fi
    
    # Add gadget configuration
    if ! grep -q "dtoverlay=dwc2" "$config_txt"; then
        cat >> "$config_txt" << EOF

# Cybersecurity Tool Configuration
dtoverlay=dwc2,dr_mode=peripheral
gpu_mem=16
dtparam=act_led_trigger=none
dtparam=act_led_activelow=on
disable_splash=1
EOF
        log "SUCCESS" "Updated /boot/config.txt"
    else
        log "INFO" "/boot/config.txt already configured"
    fi
    
    # Configure /etc/modules
    local modules_needed=("dwc2" "g_hid" "g_mass_storage")
    
    for module in "${modules_needed[@]}"; do
        if ! grep -q "^$module$" /etc/modules; then
            echo "$module" >> /etc/modules
            log "INFO" "Added $module to /etc/modules"
        fi
    done
    
    log "SUCCESS" "USB gadget mode configured"
}

# Create virtual USB storage
create_virtual_storage() {
    log "INFO" "Creating virtual USB storage..."
    
    # Create USB image file
    if [[ ! -f "$USB_IMAGE" ]]; then
        dd if=/dev/zero of="$USB_IMAGE" bs=1M count="$USB_SIZE"
        log "SUCCESS" "Created USB image file ($USB_SIZE MB)"
    else
        log "INFO" "USB image file already exists"
    fi
    
    # Format as exFAT
    mkfs.exfat -n "$USB_LABEL" "$USB_IMAGE"
    log "SUCCESS" "Formatted USB image as exFAT"
    
    # Create mount point
    mkdir -p "$MOUNT_POINT"
    
    # Add to fstab
    local fstab_entry="$USB_IMAGE $MOUNT_POINT exfat defaults,uid=pi,gid=pi 0 0"
    if ! grep -q "$USB_IMAGE" /etc/fstab; then
        echo "$fstab_entry" >> /etc/fstab
        log "SUCCESS" "Added mount entry to /etc/fstab"
    else
        log "INFO" "Mount entry already exists in /etc/fstab"
    fi
    
    # Mount the filesystem
    mount -a
    log "SUCCESS" "Virtual storage created and mounted"
}

# Deploy payload files
deploy_payloads() {
    log "INFO" "Deploying payload files..."
    
    # Ensure mount point is accessible
    if [[ ! -d "$MOUNT_POINT" ]]; then
        log "ERROR" "Mount point not accessible: $MOUNT_POINT"
        return 1
    fi
    
    # Copy payload files
    local src_dir="$PROJECT_ROOT/src"
    
    if [[ -d "$src_dir/tools" ]]; then
        cp "$src_dir/tools/detect_os.py" "$MOUNT_POINT/"
        cp "$src_dir/tools/encrypt_data.py" "$MOUNT_POINT/"
        log "SUCCESS" "Copied tool files"
    fi
    
    if [[ -d "$src_dir/payloads" ]]; then
        cp "$src_dir/payloads/windows_payload.ps1" "$MOUNT_POINT/"
        cp "$src_dir/payloads/macos_payload.sh" "$MOUNT_POINT/"
        log "SUCCESS" "Copied payload files"
    fi
    
    # Make scripts executable
    chmod +x "$MOUNT_POINT"/*.py "$MOUNT_POINT"/*.sh 2>/dev/null || true
    
    log "SUCCESS" "Payload files deployed"
}

# Create system service
create_service() {
    log "INFO" "Creating system service..."
    
    # Create payload runner script
    local runner_script="/usr/bin/payload_runner.sh"
    cat > "$runner_script" << 'EOF'
#!/bin/bash

# Cybersecurity Tool Payload Runner
# Educational tool for authorized security testing

set -euo pipefail

# Configuration
MOUNT_POINT="/mnt/usb_share"
LOG_FILE="/var/log/cybersec-tool.log"

# Logging function
log_message() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" >> "$LOG_FILE"
}

log_message "=== CYBERSECURITY TOOL STARTED ==="
log_message "Educational tool for authorized testing only"

# Ethical LED indicator (GPIO 17)
setup_led() {
    if [[ -d /sys/class/gpio ]]; then
        echo 17 > /sys/class/gpio/export 2>/dev/null || true
        echo out > /sys/class/gpio/gpio17/direction 2>/dev/null || true
        
        # Blink 3 times as ethical warning
        for i in {1..3}; do
            echo 1 > /sys/class/gpio/gpio17/value 2>/dev/null || true
            sleep 0.3
            echo 0 > /sys/class/gpio/gpio17/value 2>/dev/null || true
            sleep 0.3
        done
        
        log_message "Ethical warning LED sequence completed"
    fi
}

# Mount virtual storage
mount_storage() {
    if ! mountpoint -q "$MOUNT_POINT"; then
        mount -a
        log_message "Virtual storage mounted"
    fi
}

# Detect target OS
detect_target_os() {
    if [[ -f "$MOUNT_POINT/detect_os.py" ]]; then
        local detected_os=$(python3 "$MOUNT_POINT/detect_os.py" 2>/dev/null || echo "unknown")
        export OS_TYPE="$detected_os"
        log_message "Detected OS: $detected_os"
        echo "$detected_os"
    else
        export OS_TYPE="unknown"
        log_message "OS detection script not found"
        echo "unknown"
    fi
}

# Execute appropriate payload
execute_payload() {
    local os_type="$1"
    log_message "Executing payload for OS: $os_type"
    
    case "$os_type" in
        "windows")
            log_message "Windows payload would execute here (HID injection simulation)"
            # In a real implementation, this would use HID gadget functionality
            ;;
        "macos")
            log_message "macOS payload would execute here (HID injection simulation)"
            # In a real implementation, this would use HID gadget functionality
            ;;
        *)
            log_message "No specific payload for OS: $os_type"
            ;;
    esac
}

# Encrypt and cleanup
cleanup_data() {
    if [[ -f "$MOUNT_POINT/encrypt_data.py" ]]; then
        python3 "$MOUNT_POINT/encrypt_data.py"
        log_message "Data encryption completed"
    fi
    
    # Secure cleanup of temporary files
    find "$MOUNT_POINT" -maxdepth 1 -type f -name "*.tmp" -exec shred -u {} \; 2>/dev/null || true
    
    log_message "Cleanup completed"
}

# Main execution
main() {
    log_message "Starting payload execution sequence"
    
    # Setup ethical indicators
    setup_led
    
    # Wait for system to stabilize
    sleep 5
    
    # Mount storage
    mount_storage
    
    # Detect OS
    local target_os=$(detect_target_os)
    
    # Execute payload (in real implementation)
    execute_payload "$target_os"
    
    # Wait for completion
    sleep 20
    
    # Encrypt and cleanup
    cleanup_data
    
    # Unmount storage
    umount "$MOUNT_POINT" 2>/dev/null || true
    
    log_message "=== CYBERSECURITY TOOL COMPLETED ==="
}

# Execute main function
main "$@"
EOF
    
    chmod +x "$runner_script"
    log "SUCCESS" "Created payload runner script"
    
    # Create systemd service
    local service_file="/etc/systemd/system/cybersec-tool.service"
    cat > "$service_file" << EOF
[Unit]
Description=Educational Cybersecurity Tool
After=network.target
Wants=network.target

[Service]
Type=oneshot
ExecStart=$runner_script
Restart=no
User=root
Group=root
Environment=PYTHONUNBUFFERED=1
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF
    
    # Enable service
    systemctl daemon-reload
    systemctl enable cybersec-tool.service
    
    log "SUCCESS" "System service created and enabled"
}

# Optimize system configuration
optimize_system() {
    log "INFO" "Optimizing system configuration..."
    
    # Disable unnecessary services
    local services_to_disable=(
        "bluetooth.service"
        "hciuart.service"
        "avahi-daemon.service"
    )
    
    for service in "${services_to_disable[@]}"; do
        if systemctl is-enabled "$service" >/dev/null 2>&1; then
            systemctl disable "$service"
            log "INFO" "Disabled $service"
        fi
    done
    
    # Configure LED
    if [[ -f /sys/class/leds/led0/brightness ]]; then
        echo 0 > /sys/class/leds/led0/brightness
        echo none > /sys/class/leds/led0/trigger
        log "INFO" "Disabled activity LED"
    fi
    
    log "SUCCESS" "System optimization completed"
}

# Final configuration
final_configuration() {
    log "INFO" "Applying final configuration..."
    
    # Update rc.local for startup
    local rc_local="/etc/rc.local"
    if [[ -f "$rc_local" ]] && ! grep -q "cybersec-tool" "$rc_local"; then
        sed -i '/^exit 0/i # Educational Cybersecurity Tool\nmount -a || true\nsystemctl start cybersec-tool.service || true\n' "$rc_local"
        log "SUCCESS" "Updated rc.local"
    fi
    
    log "SUCCESS" "Final configuration applied"
}

# Main setup function
main() {
    log "INFO" "Starting Raspberry Pi Cybersecurity Tool setup..."
    
    show_disclaimer
    check_root
    update_system
    install_dependencies
    configure_usb_gadget
    create_virtual_storage
    deploy_payloads
    create_service
    optimize_system
    final_configuration
    
    echo
    log "SUCCESS" "Setup completed successfully!"
    echo
    echo -e "${GREEN}=================================${NC}"
    echo -e "${GREEN}  SETUP COMPLETED SUCCESSFULLY  ${NC}"
    echo -e "${GREEN}=================================${NC}"
    echo
    echo "Next steps:"
    echo "1. Reboot the Raspberry Pi: sudo reboot"
    echo "2. Test the USB gadget functionality"
    echo "3. Review the logs: journalctl -u cybersec-tool.service"
    echo "4. Always ensure you have permission before testing!"
    echo
    echo -e "${YELLOW}Remember: This tool is for education and authorized testing only!${NC}"
}

# Run main function
main "$@"