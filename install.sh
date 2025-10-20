#!/bin/bash

# ==============================================================================
# Storj.Cloud Agent Automated Installer (Advanced Multi-Node Version)
#
# This script automates the entire setup process for the client agent, including:
# 1. Dependency checks.
# 2. Automatic detection of Storj node containers.
# 3. An interactive wizard for node configuration.
# 4. Resilient node registration with manual token fallback.
# 5. Creation and enabling of true parallel systemd services for each node.
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
echo " Storj.Cloud Agent Installer"
echo "========================================="
echo "This script will help you detect and configure your Storj nodes."
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
mapfile -t detected_nodes < <(docker ps -a --filter "ancestor=storjlabs/storagenode" --format '{{.Names}}')

if [ ${#detected_nodes[@]} -eq 0 ]; then
    echo "No running or stopped Storj node containers found. Exiting."
    exit 1
fi

echo "Found the following ${#detected_nodes[@]} Storj node container(s):"
for name in "${detected_nodes[@]}"; do
    echo " - ${name}"
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

# --- Step 4: Interactive Node Configuration ---
echo "--- Step 4: Interactive Node Configuration ---"
read -p "How many nodes would you like to configure now? " num_to_configure

node_configs=()
configured_node_names=()
for (( i=1; i<=num_to_configure; i++ )); do
    echo ""
    echo "--- Configuring Node ${i} of ${num_to_configure} ---"
    
    echo "Please choose a container to configure:"
    select container_name in "${detected_nodes[@]}"; do
        if [[ -n "$container_name" ]]; then
            break
        else
            echo "Invalid selection. Please try again."
        fi
    done

    read -p "Please enter the public API port for '${container_name}' (e.g., 14000): " port_mapping

    if ! [[ "$port_mapping" =~ ^[0-9]+$ ]]; then
        echo "Invalid port number. Skipping this node."
        continue
    fi

    echo "Processing node '${container_name}' on port ${port_mapping}..."
    node_api_url="http://localhost:${port_mapping}"
    node_id=""
    
    echo "Attempting to fetch Node ID..."
    identity_response=$(curl -sL --connect-timeout 5 "${node_api_url}/api/sno/" || true)
    if echo "$identity_response" | jq -e '.nodeID' > /dev/null 2>&1; then
        node_id=$(echo "$identity_response" | jq -r '.nodeID')
        echo " - Node ID found: ${node_id}"
    else
        echo "----------------------------------------------------------------"
        echo "ERROR: Could not automatically determine Node ID."
        echo "The API at '${node_api_url}' did not return a valid response."
        echo "Last Response: ${identity_response}"
        echo "Please check if the node is running and the port is correct."
        echo "----------------------------------------------------------------"
        echo "Skipping this node."
        continue
    fi
    
    echo "Registering '${container_name}' with the dashboard..."
    register_payload=$(jq -n --arg name "$container_name" --arg id "$node_id" --arg host "$node_api_url" '{name: $name, storj_node_id: $id, hostname: $host}')
    register_response=$(curl -s -X POST -H "Authorization: Bearer $jwt_token" -H "Content-Type: application/json" -d "$register_payload" "${DASHBOARD_API_URL}/nodes/")
    
    auth_token=""
    if echo "$register_response" | jq -e '.node.auth_token' > /dev/null 2>&1; then
        auth_token=$(echo "$register_response" | jq -r '.node.auth_token')
        echo " - Successfully registered. Auth Token received."
    else
        echo " - Automatic registration failed. This node may already exist on your dashboard."
        echo "   Please find this node on your Storj.Cloud dashboard, go to its settings, and copy its 'Auth Token'."
        read -p "   Paste the Auth Token here: " manual_auth_token
        if [ -n "$manual_auth_token" ]; then
            auth_token=$manual_auth_token
        else
            echo "No auth token provided. Skipping this node."
            continue
        fi
    fi

    read -p " - Please enter the full path to the log file for this node: " log_file_path

    config_entry=$(jq -n --arg name "$container_name" --arg apiUrl "$node_api_url/api" --arg authToken "$auth_token" --arg logPath "$log_file_path" '{name: $name, node_api_url: $apiUrl, auth_token: $authToken, log_file_path: $logPath}')
    node_configs+=("$config_entry")
    configured_node_names+=("$container_name")
done

if [ ${#node_configs[@]} -eq 0 ]; then
    echo "No nodes were successfully configured. Exiting."
    exit 1
fi

# --- Step 5: Create Configuration File ---
echo ""
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

# API Poller Service (monitors all nodes in one go)
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
# The %i will be the node's container name
ExecStart=${VENV_DIR}/bin/python3 log_interpreter.py %i
Restart=always
Environment="DASHBOARD_API_URL=${DASHBOARD_API_URL}"
Environment="CONFIG_FILE_PATH=${CONFIG_FILE}"

[Install]
WantedBy=multi-user.target
EOL

echo "Reloading systemd, enabling and starting services..."
sudo systemctl daemon-reload
sudo systemctl enable --now storj-cloud-poller.service

# Enable and start a log interpreter instance for each configured node
for name in "${configured_node_names[@]}"; do
    echo " - Starting log interpreter for ${name}"
    sudo systemctl enable --now "storj-cloud-interpreter@${name}.service"
done

echo ""
echo "============================================="
echo " [SUCCESS] Installation Complete!"
echo "============================================="
echo "The agent is now running and sending data to your dashboard."
echo "You can check the status of the services with:"
echo "  sudo systemctl status storj-cloud-poller.service"
for name in "${configured_node_names[@]}"; do
    echo "  sudo systemctl status storj-cloud-interpreter@${name}.service"
done

