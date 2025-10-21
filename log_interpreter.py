import os
import sys
import time
import json
import re
import logging
import requests
from typing import Dict, Any, List, Optional

# --- Configuration ---
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

# Load global configuration from environment variables
DASHBOARD_API_URL = os.getenv('DASHBOARD_API_URL')
LOG_POLL_INTERVAL = int(os.getenv('LOG_POLL_INTERVAL', 60)) # seconds
BATCH_SIZE = 10
CONFIG_FILE_PATH = os.getenv('CONFIG_FILE_PATH', '/etc/storj-cloud-agent/config.json')

# --- Log Parsing Logic ---
LOG_LINE_REGEX = re.compile(
    r'^(?P<timestamp>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z)\s+'
    r'(?P<level>\S+)\s+'
    r'(?P<subsystem>\S+)\s*'
    r'(?P<message>.*)'
)

def parse_log_line(line: str) -> Optional[Dict[str, Any]]:
    """
    Parses a single log line, extracting all relevant data for the heatmap.
    """
    match = LOG_LINE_REGEX.match(line)
    if not match:
        return None

    data = match.groupdict()
    json_data = {}
    message_text = data.get('message', '').strip()
    
    event_type = data['subsystem']
    log_message = message_text

    # Find the start of the JSON object
    json_start_index = message_text.find('{')
    if json_start_index != -1:
        json_string = message_text[json_start_index:]
        try:
            json_data = json.loads(json_string)
            prefix_text = message_text[:json_start_index].strip()
            if prefix_text:
                event_type = f"{data['subsystem']}:{prefix_text}"
                log_message = prefix_text
            elif 'error' in json_data:
                log_message = json_data['error']
        except json.JSONDecodeError:
            pass

    remote_ip = None
    remote_address = json_data.get('Remote Address')
    if remote_address and isinstance(remote_address, str):
        remote_ip = remote_address.split(':')[0]

    return {
        'timestamp': data['timestamp'],
        'severity': data['level'],
        'event_type': event_type,
        'message': log_message,
        'remote_ip': remote_ip,
        'log_action': json_data.get('Action'),
        'data_size': json_data.get('Size') # NEW: Extract the data transfer size
    }

def follow_log_file(filepath: str):
    """Yields new lines from a file as they are written."""
    while True:
        try:
            with open(filepath, 'r') as file:
                file.seek(0, 2)
                while True:
                    line = file.readline()
                    if not line:
                        time.sleep(0.1)
                        continue
                    yield line
        except FileNotFoundError:
            logging.error(f"Log file not found: {filepath}. Retrying in 30 seconds.")
            time.sleep(30)
        except Exception as e:
            logging.error(f"Error reading log file {filepath}: {e}. Retrying in 30 seconds.")
            time.sleep(30)

# --- Data Submission ---
def submit_logs_to_dashboard(node_auth_token: str, logs: List[Dict[str, Any]]):
    """Submits a batch of parsed logs to the central dashboard."""
    if not DASHBOARD_API_URL:
        logging.error("DASHBOARD_API_URL not set. Cannot submit data.")
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
        logging.info(f"Successfully submitted {len(logs)} log entries for token ...{node_auth_token[-4:]}")
    except requests.exceptions.RequestException as e:
        logging.error(f"Failed to submit logs to dashboard: {e}")

# --- Main Execution Logic ---
def get_node_config_by_name(node_name: str) -> Optional[Dict[str, Any]]:
    """Finds a specific node's configuration by its name with detailed error handling."""
    try:
        with open(CONFIG_FILE_PATH, 'r') as f:
            config = json.load(f)
            for node in config.get('nodes', []):
                if node.get('name') == node_name:
                    return node
            return None
    except FileNotFoundError:
        logging.error(f"Config file not found: {CONFIG_FILE_PATH}")
        return None
    except json.JSONDecodeError as e:
        logging.error(f"Failed to parse '{CONFIG_FILE_PATH}'. It is not valid JSON.")
        logging.error(f"JSONDecodeError: {e}")
        return None

def main(target_node_name: str):
    """Main function to process logs for a specific node."""
    logging.info(f"Starting Log Interpreter for node: {target_node_name}")
    
    node_config = get_node_config_by_name(target_node_name)
    if not node_config:
        logging.critical(f"Could not load config for '{target_node_name}'. Exiting.")
        time.sleep(60)
        return

    log_path = node_config.get('log_file_path')
    auth_token = node_config.get('auth_token')

    if not all([log_path, auth_token]):
        logging.error(f"Node '{target_node_name}' is missing config. Exiting.")
        return

    logging.info(f"Beginning to tail log file: {log_path}")
    
    log_batch = []
    last_send_time = time.time()

    for line in follow_log_file(log_path):
        parsed_log = parse_log_line(line)
        if parsed_log:
            log_batch.append(parsed_log)

        time_since_last_send = time.time() - last_send_time
        if len(log_batch) >= BATCH_SIZE or (log_batch and time_since_last_send >= LOG_POLL_INTERVAL):
            submit_logs_to_dashboard(auth_token, log_batch)
            log_batch = []
            last_send_time = time.time()

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 log_interpreter.py <node_name>")
        sys.exit(1)
    
    node_name_to_process = sys.argv[1]
    main(node_name_to_process)

