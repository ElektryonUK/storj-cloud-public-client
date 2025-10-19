import os
import time
import json
import re
import logging
import requests
from typing import Dict, Any, List, Optional, Tuple

# --- Configuration ---
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

# Load global configuration from environment variables
DASHBOARD_API_URL = os.getenv('DASHBOARD_API_URL')
LOG_POLL_INTERVAL = int(os.getenv('LOG_POLL_INTERVAL', 60)) # seconds
BATCH_SIZE = 50
CONFIG_FILE_PATH = os.getenv('CONFIG_FILE_PATH', '/etc/storj-cloud-agent/config.json')

# --- Log Parsing Logic ---

# Pre-compile regex for performance. This captures the main parts of a log line.
LOG_LINE_REGEX = re.compile(
    r'^(?P<timestamp>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z)\s+'
    r'(?P<level>INFO|WARN|ERROR|FATAL|DEBUG)\s+'
    r'(?P<subsystem>[^ ]+)\s+'
    r'(?P<message>.*)'
)

def parse_log_line(line: str) -> Optional[Dict[str, Any]]:
    """Parses a single log line into a structured dictionary."""
    match = LOG_LINE_REGEX.match(line)
    if not match:
        return None

    data = match.groupdict()
    
    # Try to parse JSON from the message part
    try:
        json_message = json.loads(data['message'])
        # Prefer a specific 'error' or 'message' field from the JSON if it exists
        if 'error' in json_message:
            data['message'] = json_message['error']
        elif 'message' in json_message:
            data['message'] = json_message['message']
        
        data.update(json_message)
    except (json.JSONDecodeError, TypeError):
        # It's not a JSON message or message is not a string, which is fine.
        pass

    return {
        'timestamp': data['timestamp'],
        'severity': data['level'],
        'message': str(data.get('message', '')), # Ensure message is a string
        'remote_ip': data.get('remote_addr') # Specifically for heatmap
    }

def follow_log_file(filepath: str):
    """Yields new lines from a file as they are written."""
    while True:
        try:
            with open(filepath, 'r') as file:
                # Go to the end of the file
                file.seek(0, 2)
                while True:
                    line = file.readline()
                    if not line:
                        time.sleep(0.1) # Wait for new lines
                        continue
                    yield line
        except FileNotFoundError:
            logging.error(f"Log file not found: {filepath}. It will be retried in 30 seconds.")
            time.sleep(30) # Wait before trying to open again
        except Exception as e:
            logging.error(f"Error reading log file {filepath}: {e}. Retrying in 30 seconds.")
            time.sleep(30)


# --- Data Submission ---

def submit_logs_to_dashboard(node_auth_token: str, logs: List[Dict[str, Any]]):
    """Submits a batch of parsed logs to the central dashboard."""
    if not DASHBOARD_API_URL:
        logging.error("DASHBOARD_API_URL environment variable not set. Cannot submit data.")
        return

    if not logs:
        return

    headers = {
        'Content-Type': 'application/json',
        'X-Node-Auth-Token': node_auth_token
    }
    try:
        response = requests.post(f"{DASHBOARD_API_URL}/data/logs", headers=headers, json={'logs': logs}, timeout=30)
        response.raise_for_status()
        logging.info(f"Successfully submitted {len(logs)} log entries for node token ending in ...{node_auth_token[-4:]}")
    except requests.exceptions.RequestException as e:
        logging.error(f"Failed to submit logs to dashboard: {e}")

# --- Main Execution Logic ---

def process_node_logs(node_config: Dict[str, Any]):
    """A dedicated process for a single node's log file."""
    node_name = node_config.get('name', 'Unknown')
    log_path = node_config.get('log_file_path')
    auth_token = node_config.get('auth_token')

    if not all([log_path, auth_token]):
        logging.error(f"Node '{node_name}' is missing 'log_file_path' or 'auth_token'. Cannot process logs.")
        return # This will stop the thread/process for this node
    
    logging.info(f"Starting log interpreter for node: {node_name} (File: {log_path})")
    
    log_batch = []
    last_send_time = time.time()

    for line in follow_log_file(log_path):
        parsed_log = parse_log_line(line)
        if parsed_log:
            log_batch.append(parsed_log)

        # Send batch if it's full or if the poll interval has passed
        time_since_last_send = time.time() - last_send_time
        if len(log_batch) >= BATCH_SIZE or (log_batch and time_since_last_send >= LOG_POLL_INTERVAL):
            submit_logs_to_dashboard(auth_token, log_batch)
            log_batch = []
            last_send_time = time.time()

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

def main():
    """Main function to start and manage log processing."""
    logging.info("Starting Storj.Cloud Log Interpreter Service.")

    if not DASHBOARD_API_URL:
        logging.error("FATAL: DASHBOARD_API_URL is not set. Exiting.")
        return

    # CRITICAL FIX: Instead of exiting, the main loop will now periodically check the config.
    # This makes the service resilient if the config file is temporarily unavailable or empty.
    while True:
        nodes = load_node_config()
        if not nodes:
            logging.warning(f"No nodes configured in {CONFIG_FILE_PATH}. Will check again in {LOG_POLL_INTERVAL} seconds.")
            time.sleep(LOG_POLL_INTERVAL)
            continue
            
        # For simplicity, we'll process the first node's log file.
        # A multi-threaded/process approach would be an enhancement for multiple log files.
        # This design assumes the user will run one agent per node if needed,
        # or that only one log file needs active tailing.
        logging.info(f"Found {len(nodes)} node(s) in config. Processing the first entry.")
        process_node_logs(nodes[0])

        # If process_node_logs ever returns (e.g., due to an unrecoverable error),
        # the outer loop will wait and then try to reload the config and start again.
        logging.error("Log processing for node stopped unexpectedly. Restarting main loop after a delay.")
        time.sleep(LOG_POLL_INTERVAL)


if __name__ == "__main__":
    main()

