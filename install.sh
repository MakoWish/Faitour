#!/bin/bash

# Log to console
log() {
    local message="$1"
    local level="${2:-INFO}"
    echo "[$level] $message"
}

# Ensure this install is being run as root/sudo
check_root() {
    if [[ "$EUID" -ne 0 ]]; then
        log "This script must be run as root." "ERROR"
        exit 1
    fi
}

# Install required packages from apt
install_apt_packages() {
    local apt_packages=(
        "build-essential"
        "libnetfilter-queue-dev"
        "python3"
        "python3-pip"
        "python3-scapy"
        "python3-pysmi"
        "python3-pyftpdlib"
        "python3-paramiko"
        "python3-psutil"
    )

    log "Updating apt package list..."
    if ! apt update -y; then
        log "Failed to update apt package list." "ERROR"
        exit 1
    fi

    log "Installing apt packages..."
    if ! apt install -y "${apt_packages[@]}" >/dev/null 2>&1; then
        log "Failed to install apt packages." "ERROR"
        exit 1
    fi

    log "Apt packages installed successfully."
}

# Install Python packages that are not available in apt
install_pip_packages() {
    local pip_packages=(
        "netfilterqueue"
        "pysnmp"
        "smbprotocol"
        "telnetlib3"
    )

    log "Installing pip packages..."
    if ! pip3 install --break-system-packages "${pip_packages[@]}" >/dev/null 2>&1; then
        log "Failed to install pip packages." "ERROR"
        exit 1
    fi

    log "Pip packages installed successfully."
}

# Create systemd service to start Faitour on system restart
create_systemd_service() {
    local service_path="/etc/systemd/system/faitour.service"
    local working_dir
    working_dir=$(pwd)

    log "Creating systemd service file..."
    cat <<EOF > "$service_path"
[Unit]
Description=Faitour Services Emulator
After=network.target

[Service]
ExecStart=/usr/bin/python3 $working_dir/faitour.py
WorkingDirectory=$working_dir
Restart=always
User=root
KillSignal=SIGINT

[Install]
WantedBy=multi-user.target
EOF

    log "Reloading systemd daemon..."
    if ! systemctl daemon-reload; then
        log "Failed to reload systemd daemon." "ERROR"
        exit 1
    fi
}

# Enable the service
enable_service() {
    log "Enabling and starting the service..."
    if ! systemctl enable faitour.service >/dev/null 2>&1; then
        log "Failed to enable systemd service." "ERROR"
        exit 1
    fi
    log "Systemd service created and enabled."
}

# Main routine
main() {
    check_root
    install_apt_packages
    install_pip_packages
    create_systemd_service
    enable_service

    log "Installation complete!"
    log "Be sure to update your network settings in './config.yml' before starting the service!"
}

# Entry point
main
