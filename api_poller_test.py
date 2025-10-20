import os
import requests
import json
import logging
from typing import Dict, Any, List

# --- Configuration ---
# This script uses the same configuration as the main agent.
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
CONFIG_FILE_PATH = os.getenv('CONFIG_FILE_PATH', '/etc/storj-cloud-agent/config.json')

# --- Helper Functions (copied from api_poller.py) ---

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

def fetch_node_data(node_api_url: str) -> Dict[str, Any]:
    """Fetches combined data from the node's API."""
    try:
        response = requests.get(f"{node_api_url}/sno", timeout=10)
        response.raise_for_status()
        return response.json()
    except requests.exceptions.RequestException as e:
        logging.error(f"Could not fetch data from {node_api_url}/sno: {e}")
        return {}

def format_stats_payload(data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Formats the raw node data into the structure expected by the dashboard API.
    """
    if not data or not isinstance(data, dict):
        logging.warning("Received empty or invalid data from node API.")
        return {}
    
    disk_space = data.get('diskSpace') or {}
    bandwidth = data.get('bandwidth') or {}
    
    first_satellite = {}
    satellites = data.get('satellites')
    if isinstance(satellites, list) and len(satellites) > 0:
        first_satellite = satellites[0] if isinstance(satellites[0], dict) else {}

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

# --- Main Test Execution Logic ---
def main():
    """Main function to run the diagnostic test."""
    print("--- Starting Storj.Cloud Agent Diagnostic Test ---")
    
    nodes = load_node_config()
    if not nodes:
        print("\nERROR: No nodes found in the configuration file. Please run the installer first.")
        return

    print(f"\nFound {len(nodes)} node(s) in '{CONFIG_FILE_PATH}'. Processing each one...")
    print("-" * 50)

    for node in nodes:
        node_name = node.get('name', 'Unknown')
        node_api = node.get('node_api_url')
        
        if not node_api:
            print(f"\nSkipping node '{node_name}' due to missing 'node_api_url'.")
            print("-" * 50)
            continue

        print(f"\n1. Testing Node: '{node_name}'")
        print(f"   Fetching data from API endpoint: {node_api}/sno")

        # Step 1: Get the raw data from the Storj Node API
        raw_data = fetch_node_data(node_api)
        
        print("\n2. RAW RESPONSE from Storj Node API:")
        # Use json.dumps for pretty printing
        print(json.dumps(raw_data, indent=4))
        
        if not raw_data:
            print("\n   -> Skipping formatting because the raw response was empty.")
            print("-" * 50)
            continue

        # Step 2: Format that raw data for our server
        stats_payload = format_stats_payload(raw_data)

        print("\n3. FORMATTED PAYLOAD (what would be sent to the server):")
        print(json.dumps(stats_payload, indent=4))

        print("\n--- Test for this node complete ---")
        print("-" * 50)
        
    print("\n--- Diagnostic Test Finished ---")


if __name__ == "__main__":
    main()
