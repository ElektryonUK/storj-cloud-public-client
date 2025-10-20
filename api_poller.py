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
    except json.JSONDecodeError as e:
        logging.error(f"Error decoding JSON from configuration file: {e}")
        return []

def fetch_api_data(base_url: str, endpoint: str) -> Dict[str, Any]:
    """
    Fetches data from a specific API endpoint with error handling.
    Requests library handles redirects by default.
    """
    url = f"{base_url}{endpoint}"
    try:
        response = requests.get(url, timeout=10)
        response.raise_for_status()
        return response.json()
    except requests.exceptions.RequestException as e:
        logging.error(f"Could not fetch data from {url}: {e}")
        return {}
    except json.JSONDecodeError:
        logging.error(f"Invalid JSON response from {url}")
        return {}

def aggregate_and_format_payload(sno_data: Dict, satellites_data: List, payout_data: Dict) -> Dict[str, Any]:
    """
    Aggregates data from all endpoints and computes derived metrics.
    """
    if not sno_data:
        return {}
        
    # --- Disk Space Calculation ---
    disk_space = sno_data.get('diskSpace', {}) or {}
    disk_used = disk_space.get('used', 0)
    disk_available = disk_space.get('available', 0)
    disk_total = disk_used + disk_available
    disk_trash = disk_space.get('trash', 0)

    # --- Bandwidth ---
    bandwidth = sno_data.get('bandwidth', {}) or {}
    bandwidth_ingress = bandwidth.get('ingress', 0)
    bandwidth_egress = bandwidth.get('egress', 0)

    # --- Satellite Score Averaging ---
    total_uptime = 0.0
    total_audit = 0.0
    total_suspension = 0.0
    satellite_count = 0
    if isinstance(satellites_data, list) and len(satellites_data) > 0:
        satellite_count = len(satellites_data)
        for sat in satellites_data:
            if isinstance(sat, dict):
                total_uptime += sat.get('uptimeScore', 0.0)
                total_audit += sat.get('auditScore', 0.0)
                total_suspension += sat.get('suspensionScore', 0.0)
    
    avg_uptime = total_uptime / satellite_count if satellite_count > 0 else 0.0
    avg_audit = total_audit / satellite_count if satellite_count > 0 else 0.0
    avg_suspension = total_suspension / satellite_count if satellite_count > 0 else 1.0

    # --- Payout Data ---
    payout_month = payout_data.get('currentMonth', {}) or {}
    estimated_payout = payout_month.get('total', 0.0)
    held_amount = payout_month.get('held', 0.0)

    # --- Assemble Final Payload for the Server ---
    return {
        "version": sno_data.get('version', 'N/A'),
        "disk_total": disk_total,
        "disk_used": disk_used,
        "disk_trash": disk_trash,
        "bandwidth_ingress": bandwidth_ingress,
        "bandwidth_egress": bandwidth_egress,
        "uptime_score": avg_uptime,
        "audit_score": avg_audit,
        "suspension_score": avg_suspension,
        "estimated_payout": estimated_payout,
        "held_amount": held_amount
    }

def submit_stats_to_dashboard(node_auth_token: str, payload: Dict[str, Any]):
    """Submits the formatted statistics payload to the central dashboard."""
    if not DASHBOARD_API_URL:
        logging.error("DASHBOARD_API_URL not set. Cannot submit data.")
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
        if e.response is not None:
            logging.error(f"Server responded with: {e.response.text}")

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

                logging.info(f"Polling comprehensive data for node: {node_name}")
                
                # Fetch from all endpoints
                sno_data = fetch_api_data(node_api, '/sno')
                satellites_data = fetch_api_data(node_api, '/sno/satellites')
                payout_data = fetch_api_data(node_api, '/sno/estimated-payout')
                
                # Aggregate and send
                stats_payload = aggregate_and_format_payload(sno_data, satellites_data, payout_data)
                submit_stats_to_dashboard(auth_token, stats_payload)
        
        logging.info(f"Sleeping for {POLL_INTERVAL} seconds...")
        time.sleep(POLL_INTERVAL)

if __name__ == "__main__":
    main()

