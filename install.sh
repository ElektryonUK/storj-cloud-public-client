#!/bin/bash

# ==============================================================================
# Storj.Cloud Agent Automated Installer
#
# This script automates the entire setup process for the client agent, including:
# 1. Dependency checks (Docker, curl, jq).
# 2. Automatic detection of Storj nodes running in Docker.
# 3. Fetching Node IDs via the local node API.
# 4. Prompting the user to log into their Storj.Cloud account.
# 5. Automatically registering the detected nodes with the dashboard.
# 6. Creating and enabling systemd services for the agent.
#
# ==============================================================================

set -e

# --- Configuration & Welcome ---
DASHBOARD_API_URL="https://devapi.storj.cloud/api/v1"
CONFIG_DIR="/etc/storj-cloud-agent"
CONFIG_FILE="${CONFIG_DIR}/config.json"
AGENT_DIR="/opt/storj-cloud-agent"
VENV_DIR="${AGENT_DIR}/venv"

echo "========================================="
echo " Storj.Cloud Agent Installer"
echo "========================================="
echo "This script will automatically detect and configure your Storj nodes."
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
check_command "docker" "docker.io"
check_command "curl" "curl"
check_command "jq" "jq"
check_command "python3" "python3"

if ! python3 -c "import venv" &> /dev/null; then
    echo "Error: python3-venv is not installed."
    echo "Please install it by running: sudo apt-get install -y python3-venv"
    exit 1
fi
echo "All dependencies found."
echo ""

# --- Step 2: Detect Storj Nodes in Docker ---
echo "--- Step 2: Detecting Storj nodes running in Docker ---"
nodes=()
while IFS= read -r line; do
    nodes+=("$line")
done < <(docker ps -a --filter "ancestor=storjlabs/storagenode" --format '{{.Names}}|{{.Ports}}')

if [ ${#nodes[@]} -eq 0 ]; then
    echo "No running or stopped Storj node containers found. Exiting."
    exit 1
fi

echo "Found ${#nodes[@]} Storj node container(s):"
for node_info in "${nodes[@]}"; do
    container_name=$(echo "$node_info" | cut -d'|' -f1)
    echo " - ${container_name}"
done
echo ""

# --- Step 3: User Login ---
echo "--- Step 3: Please log in to your Storj.Cloud account ---"
read -p "Enter your dashboard email: " email
read -s -p "Enter your dashboard password: " password
echo ""

echo "Authenticating..."
login_response=$(curl -s -X POST -H "Content-Type: application/json" \
    -d "{\"email\":\"$email\", \"password\":\"$password\"}" \
    "${DASHBOARD_API_URL}/auth/login")

jwt_token=$(echo "$login_response" | jq -r '.token')

if [ -z "$jwt_token" ] || [ "$jwt_token" == "null" ]; then
    echo "Login failed. Please check your credentials and try again."
    exit 1
fi
echo "Login successful."
echo ""

# --- Step 4: Fetch Node Details and Register ---
echo "--- Step 4: Fetching node details and registering with the dashboard ---"
node_configs=()
for node_info in "${nodes[@]}"; do
    container_name=$(echo "$node_info" | cut -d'|' -f1)
    port_mapping=$(echo "$node_info" | cut -d'|' -f2 | grep -oP '0\.0\.0\.0:\K[0-9]+(?=->14002/tcp)')
    
    if [ -z "$port_mapping" ]; then
        echo "Warning: Could not determine API port for container '${container_name}'. Skipping."
        continue
    fi

    echo "Processing node '${container_name}' on port ${port_mapping}..."
    node_api_url="http://localhost:${port_mapping}"

    # Fetch Node ID
    identity_response=$(curl -s "${node_api_url}/api/sno/identity")
    node_id=$(echo "$identity_response" | jq -r '.nodeID')

    if [ -z "$node_id" ] || [ "$node_id" == "null" ]; then
        echo "Warning: Could not fetch Node ID for '${container_name}'. Skipping."
        continue
    fi
    echo " - Node ID: ${node_id}"

    # Register Node with Dashboard
    register_payload=$(jq -n \
        --arg name "$container_name" \
        --arg id "$node_id" \
        --arg host "$node_api_url" \
        '{name: $name, storj_node_id: $id, hostname: $host}')
        
    register_response=$(curl -s -X POST -H "Authorization: Bearer $jwt_token" -H "Content-Type: application/json" \
        -d "$register_payload" \
        "${DASHBOARD_API_URL}/nodes/")

    auth_token=$(echo "$register_response" | jq -r '.node.auth_token')

    if [ -z "$auth_token" ] || [ "$auth_token" == "null" ]; then
        echo "Warning: Failed to register '${container_name}' with the dashboard. It may already be registered. Skipping."
        continue
    fi
    echo " - Successfully registered. Auth Token received."

    # Ask for log path
    read -p " - Please enter the full path to the log file for this node: " log_file_path

    # Add to our config list
    config_entry=$(jq -n \
        --arg name "$container_name" \
        --arg apiUrl "$node_api_url/api" \
        --arg authToken "$auth_token" \
        --arg logPath "$log_file_path" \
        '{name: $name, node_api_url: $apiUrl, auth_token: $authToken, log_file_path: $logPath}')
    node_configs+=("$config_entry")
    echo ""
done

# --- Step 5: Create Configuration File ---
echo "--- Step 5: Creating agent configuration file ---"
sudo mkdir -p "$CONFIG_DIR"
config_json=$(jq -n --argjson nodes "[$(IFS=,; echo "${node_configs[*]}")]" '{nodes: $nodes}')
echo "$config_json" | sudo tee "$CONFIG_FILE" > /dev/null
sudo chmod 644 "$CONFIG_FILE"
echo "Configuration saved to ${CONFIG_FILE}"
echo ""

# --- Step 6: Install Agent Files ---
echo "--- Step 6: Installing agent scripts and dependencies ---"
sudo mkdir -p "$AGENT_DIR"
sudo cp api_poller.py log_interpreter.py requirements.txt "$AGENT_DIR/"

echo "Creating Python virtual environment..."
sudo python3 -m venv "$VENV_DIR"
sudo "$VENV_DIR/bin/pip" install -r "$AGENT_DIR/requirements.txt"
sudo chown -R root:root "$AGENT_DIR"
echo "Agent files installed in ${AGENT_DIR}"
echo ""

# --- Step 7: Create systemd Services ---
echo "--- Step 7: Creating and enabling systemd services ---"

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

# Log Interpreter Service
sudo bash -c "cat > /etc/systemd/system/storj-cloud-interpreter.service" <<EOL
[Unit]
Description=Storj.Cloud Dashboard Log Interpreter
After=network.target

[Service]
User=root
Group=root
WorkingDirectory=${AGENT_DIR}
ExecStart=${VENV_DIR}/bin/python3 log_interpreter.py
Restart=always
Environment="DASHBOARD_API_URL=${DASHBOARD_API_URL}"
Environment="CONFIG_FILE_PATH=${CONFIG_FILE}"

[Install]
WantedBy=multi-user.target
EOL

echo "Reloading systemd, enabling and starting services..."
sudo systemctl daemon-reload
sudo systemctl enable --now storj-cloud-poller.service
sudo systemctl enable --now storj-cloud-interpreter.service

echo ""
echo "============================================="
echo " [SUCCESS] Installation Complete!"
echo "============================================="
echo "The agent is now running and sending data to your dashboard."
echo "You can check the status of the services with:"
echo "  sudo systemctl status storj-cloud-poller.service"
echo "  sudo systemctl status storj-cloud-interpreter.service"
