#!/bin/bash

# ==============================================================================
# Storj.Cloud Agent Installer (Simplified Testing Version)
#
# This script automates the setup of the agent services for a known machine.
# It creates a placeholder config file and restarts the services.
#
# ==============================================================================

# Exit immediately if a command exits with a non-zero status.
set -e

# --- Configuration & Welcome ---
DASHBOARD_API_URL="https://devapi.storj.cloud/api/v1"
CONFIG_DIR="/etc/storj-cloud-agent"
CONFIG_FILE="${CONFIG_DIR}/config.json"
AGENT_DIR="/opt/storj-cloud-agent"
VENV_DIR="${AGENT_DIR}/venv"

echo "========================================="
echo " Storj.Cloud Agent Installer (Testing Mode)"
echo "========================================="
echo ""

# --- Helper Functions ---
function check_command() {
    if ! command -v "$1" &> /dev/null; then
        echo "Error: Command '$1' is not found."
        echo "Please install it and run this script again."
        if [ -x "$(command -v apt-get)" ]; then
            echo "You can try running: sudo apt-get install -y $2"
        fi
        exit 1
    fi
}

# --- Step 1: Pre-flight Checks ---
echo "--- Step 1: Checking dependencies ---"
check_command "python3" "python3"
if ! python3 -c "import venv" &> /dev/null; then
    echo "Error: python3-venv is not installed."
    echo "Please install it by running: sudo apt-get install -y python3-venv"
    exit 1
fi
echo "Dependencies found."
echo ""

# --- Step 2: Create Configuration File (if it doesn't exist) ---
echo "--- Step 2: Checking for agent configuration file ---"
sudo mkdir -p "$CONFIG_DIR"
if [ ! -f "$CONFIG_FILE" ]; then
    echo "Configuration file not found. Creating a new placeholder."
    sudo bash -c "cat > $CONFIG_FILE" <<EOL
{
    "nodes": [
        {
            "name": "storagenode01",
            "node_api_url": "http://localhost:14000/api",
            "auth_token": "PASTE_YOUR_AUTH_TOKEN_HERE",
            "log_file_path": "/path/to/your/storagenode.log"
        }
    ]
}
EOL
    sudo chmod 644 "$CONFIG_FILE"
    echo "Placeholder configuration saved to ${CONFIG_FILE}"
    echo "IMPORTANT: Please edit this file with your actual auth_token and log_file_path before the agent can work."
else
    echo "Existing configuration file found at ${CONFIG_FILE}. Skipping creation."
fi
echo ""

# --- Step 3: Install Agent Files ---
echo "--- Step 3: Installing agent scripts and dependencies ---"
sudo mkdir -p "$AGENT_DIR"
# Assuming script is run from a dir containing these files
sudo cp api_poller.py log_interpreter.py requirements.txt "$AGENT_DIR/"

echo "Creating Python virtual environment if it doesn't exist..."
if [ ! -d "$VENV_DIR" ]; then
    sudo python3 -m venv "$VENV_DIR"
fi

sudo "$VENV_DIR/bin/pip" install -r "$AGENT_DIR/requirements.txt"
sudo chown -R root:root "$AGENT_DIR"
echo "Agent files installed in ${AGENT_DIR}"
echo ""

# --- Step 4: Create and Restart systemd Services ---
echo "--- Step 4: Creating and restarting systemd services ---"

# API Poller Service
sudo bash -c "cat > /etc/systemd/system/storj-cloud-poller.service" <<EOL
[Unit]
Description=Storj.Cloud Dashboard API Poller
After=network.target

[Service]
User=root
Group=root
WorkingDirectory=${AGENT_DIR}
ExecStart=${VENV_DIR}/bin/python3 api_poller.py
Restart=always
Environment="DASHBOARD_API_URL=${DASHBOARD_API_URL}"
Environment="CONFIG_FILE_PATH=${CONFIG_FILE}"

[Install]
WantedBy=multi-user.target
EOL

# Log Interpreter Service TEMPLATE for multi-node support
sudo bash -c "cat > /etc/systemd/system/storj-cloud-interpreter@.service" <<EOL
[Unit]
Description=Storj.Cloud Log Interpreter for %i
After=network.target

[Service]
User=root
Group=root
WorkingDirectory=${AGENT_DIR}
ExecStart=${VENV_DIR}/bin/python3 log_interpreter.py %i
Restart=always
Environment="DASHBOARD_API_URL=${DASHBOARD_API_URL}"
Environment="CONFIG_FILE_PATH=${CONFIG_FILE}"

[Install]
WantedBy=multi-user.target
EOL

echo "Reloading systemd daemon and restarting services..."
sudo systemctl daemon-reload
sudo systemctl enable storj-cloud-poller.service
# The name 'storagenode01' is hardcoded to match the placeholder config
sudo systemctl enable "storj-cloud-interpreter@storagenode01.service"

# CRITICAL CHANGE: Restart services to apply new code/config
sudo systemctl restart storj-cloud-poller.service
sudo systemctl restart "storj-cloud-interpreter@storagenode01.service"

echo ""
echo "============================================="
echo " [SUCCESS] Agent Re-installation Complete!"
echo "============================================="
echo "The agent services have been restarted."
echo "You can check their status with:"
echo "  sudo systemctl status storj-cloud-poller.service"
echo "  sudo systemctl status storj-cloud-interpreter@storagenode01.service"

