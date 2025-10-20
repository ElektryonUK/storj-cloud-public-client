import os
import requests
import json
import logging
from typing import Dict, Any, List, Optional

# --- Configuration ---
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
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

def aggregate_and_format_payload(sno_data: Dict, satellites_data: Dict, payout_data: Dict) -> Dict[str, Any]:
    """
    DEFINITIVE FIX: Aggregates data from all endpoints and computes derived metrics
    based on the actual raw JSON structure.
    """
    if not sno_data:
        return {}
        
    # --- Node Info ---
    node_id = sno_data.get('nodeID', 'N/A')
    wallet = sno_data.get('wallet', 'N/A')
    version = sno_data.get('version', 'N/A')

    # --- Disk Space Calculation ---
    disk_space = sno_data.get('diskSpace', {}) or {}
    disk_used = disk_space.get('used', 0)
    disk_available = disk_space.get('available', 0)
    disk_total = disk_used + disk_available
    disk_trash = disk_space.get('trash', 0)

    # --- Bandwidth Calculation (from satellites endpoint) ---
    bandwidth_ingress = 0
    bandwidth_egress = 0
    daily_bw = (satellites_data or {}).get('bandwidthDaily', [])
    if isinstance(daily_bw, list) and len(daily_bw) > 0:
        latest_day = daily_bw[-1] # Get the most recent day's data
        if isinstance(latest_day, dict):
            ingress_data = latest_day.get('ingress', {}) or {}
            egress_data = latest_day.get('egress', {}) or {}
            bandwidth_ingress = ingress_data.get('repair', 0) + ingress_data.get('usage', 0)
            bandwidth_egress = egress_data.get('repair', 0) + egress_data.get('audit', 0) + egress_data.get('usage', 0)

    # --- Satellite Score Averaging (from audits array) ---
    total_uptime = 0.0
    total_audit = 0.0
    total_suspension = 0.0
    audits_list = (satellites_data or {}).get('audits', [])
    satellite_count = 0
    if isinstance(audits_list, list) and len(audits_list) > 0:
        satellite_count = len(audits_list)
        for sat in audits_list:
            if isinstance(sat, dict):
                total_uptime += sat.get('onlineScore', 0.0) # Correct key is onlineScore
                total_audit += sat.get('auditScore', 0.0)
                total_suspension += sat.get('suspensionScore', 0.0)
    
    avg_uptime = total_uptime / satellite_count if satellite_count > 0 else 0.0
    avg_audit = total_audit / satellite_count if satellite_count > 0 else 0.0
    avg_suspension = total_suspension / satellite_count if satellite_count > 0 else 1.0

    # --- Payout Data ---
    payout_month = payout_data.get('currentMonth', {}) or {}
    estimated_payout = payout_month.get('payout', 0.0) # Correct key is payout
    held_amount = payout_month.get('held', 0.0)

    # --- Assemble Final Payload ---
    return {
        "node_id": node_id,
        "wallet": wallet,
        "version": version,
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


# --- Main Test Execution Logic ---
def main():
    """Main function to run the diagnostic test."""
    print("--- Starting Storj.Cloud Agent Comprehensive Diagnostic Test ---")
    
    nodes = load_node_config()
    if not nodes:
        print(f"\nERROR: No nodes found in '{CONFIG_FILE_PATH}'. Please run the installer first.")
        return

    print(f"\nFound {len(nodes)} node(s). Processing each one...")
    print("-" * 60)

    for node in nodes:
        node_name = node.get('name', 'Unknown')
        node_api = node.get('node_api_url')
        
        if not node_api:
            print(f"\nSkipping node '{node_name}' due to missing 'node_api_url'.")
            print("-" * 60)
            continue

        print(f"\n1. Testing Node: '{node_name}'")
        print(f"   Using Base API URL: {node_api}")

        # --- Step 1: Fetch data from all endpoints ---
        print("\n2. Fetching RAW data from all required API endpoints...")
        sno_data = fetch_api_data(node_api, '/sno')
        satellites_data = fetch_api_data(node_api, '/sno/satellites')
        payout_data = fetch_api_data(node_api, '/sno/estimated-payout')
        
        # --- Step 2: Print RAW data for debugging ---
        print("\n3. RAW JSON Responses Received:")
        print("\n--- RAW from /api/sno ---")
        print(json.dumps(sno_data, indent=4))
        print("\n--- RAW from /api/sno/satellites ---")
        print(json.dumps(satellites_data, indent=4))
        print("\n--- RAW from /api/sno/estimated-payout ---")
        print(json.dumps(payout_data, indent=4))

        if not sno_data:
            print("\n   -> CRITICAL: Cannot proceed without data from /api/sno. Skipping node.")
            print("-" * 60)
            continue
            
        # --- Step 3: Aggregate, compute, and format the payload ---
        print("\n4. Aggregating and formatting the final payload...")
        final_payload = aggregate_and_format_payload(sno_data, satellites_data, payout_data)

        print("\n5. FINAL AGGREGATED PAYLOAD (what would be sent to the server):")
        print(json.dumps(final_payload, indent=4))

        print("\n--- Test for this node complete ---")
        print("-" * 60)
        
    print("\n--- Diagnostic Test Finished ---")


if __name__ == "__main__":
    main()

