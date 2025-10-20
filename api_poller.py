import os
import time
import requests
import json
import logging
from typing import Dict, Any, List

# --- Configuration ---
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

# Load global configuration from environment variables
DASHBOARD_API_URL = os.getenv('DASHBOARD_API_URL')
POLL_INTERVAL = int(os.getenv('POLL_INTERVAL', 900))  # 15 minutes default
CONFIG_FILE_PATH = os.getenv('CONFIG_FILE_PATH', '/etc/storj-cloud-agent/config.json')

# --- Helper Functions ---

def load_node_config() -> List[Dict[str, str]]:
    """Loads the multi-node configuration from the JSON file."""
    try:
        with open(CONFIG_FILE_PATH, 'r') as f:
            config = json.load(f)
            return config.get('nodes', [])
    except FileNotFoundError:
        logging.error(f"Configuration file not found at: {CONFIG_FILE_PATH}")
        return []
    except json.JSONDecodeError:
        logging.error(f"Error decoding JSON from configuration file: {CONFIG_FILE_PATH}")
        return []

def fetch_node_data(node_api_url: str) -> Dict[str, Any]:
    """Fetches combined data from the node's API."""
    try:
        # Using -L to follow redirects is safer.
        response = requests.get(f"{node_api_url}/sno", timeout=10)
        response.raise_for_status()
        return response.json()
    except requests.exceptions.RequestException as e:
        logging.error(f"Could not fetch data from {node_api_url}/sno: {e}")
        return {}

def format_stats_payload(data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Formats the raw node data into the structure expected by the dashboard API.
    This version is highly resilient and extracts more data points.
    """
    if not data:
        return {}
    
    # Safely get nested satellite data
    first_satellite = {}
    satellites = data.get('satellites', [])
    if satellites and isinstance(satellites, list) and len(satellites) > 0:
        first_satellite = satellites[0] if isinstance(satellites[0], dict) else {}

    # DEFINITIVE FIX: Use nested .get() for every value and handle potential None types.
    disk_space = data.get('diskSpace', {}) or {}
    bandwidth = data.get('bandwidth', {}) or {}

    return {
        "version": data.get('version', 'N/A'),
        "disk_total": disk_space.get('total', 0),
        "disk_used": disk_space.get('used', 0),
        "disk_trash": disk_space.get('trash', 0),
        "bandwidth_ingress": bandwidth.get('ingress', 0),
        "bandwidth_egress": bandwidth.get('egress', 0),
        "uptime_score": first_satellite.get('uptimeScore', 0.0),
        "audit_score": first_satellite.get('auditScore', 0.0),
        "suspension_score": first_satellite.get('suspensionScore', 0.0),
        "estimated_payout": data.get('estimatedPayout', 0.0),
        "held_amount": data.get('heldAmount', 0.0)
    }

def submit_stats_to_dashboard(node_auth_token: str, payload: Dict[str, Any]):
    """Submits the formatted statistics payload to the central dashboard."""
    if not DASHBOARD_API_URL:
        logging.error("DASHBOARD_API_URL environment variable not set. Cannot submit data.")
        return

    if not payload:
        logging.warning("Payload is empty, skipping submission.")
        return

    headers = {
        'Content-Type': 'application/json',
        'X-Node-Auth-Token': node_auth_token
    }
    try:
        response = requests.post(f"{DASHBOARD_API_URL}/data/stats", headers=headers, json=payload, timeout=30)
        response.raise_for_status()
        logging.info(f"Successfully submitted stats for node token ending in ...{node_auth_token[-4:]}")
    except requests.exceptions.RequestException as e:
        logging.error(f"Failed to submit stats to dashboard: {e}")

# --- Main Execution Logic ---

def main():
    """Main loop to poll nodes and submit data."""
    logging.info("Starting Storj.Cloud API Poller Service.")
    
    if not DASHBOARD_API_URL:
        logging.error("FATAL: DASHBOARD_API_URL is not set. Exiting.")
        return

    while True:
        nodes = load_node_config()
        if not nodes:
            logging.warning(f"No nodes configured in {CONFIG_FILE_PATH}. Waiting...")
        else:
            logging.info(f"Found {len(nodes)} node(s) to poll.")
            for node in nodes:
                node_name = node.get('name', 'Unknown')
                node_api = node.get('node_api_url')
                auth_token = node.get('auth_token')

                if not all([node_api, auth_token]):
                    logging.error(f"Node '{node_name}' is missing 'node_api_url' or 'auth_token'. Skipping.")
                    continue

                logging.info(f"Polling data for node: {node_name}")
                raw_data = fetch_node_data(node_api)
                stats_payload = format_stats_payload(raw_data)
                submit_stats_to_dashboard(auth_token, stats_payload)
        
        logging.info(f"Sleeping for {POLL_INTERVAL} seconds...")
        time.sleep(POLL_INTERVAL)

if __name__ == "__main__":
    main()

